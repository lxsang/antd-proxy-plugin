#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define PLUGIN_IMPLEMENT 1
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <antd/plugin.h>
#include <antd/scheduler.h>
#include <antd/ini.h>
#include <antd/utils.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>

typedef struct
{
    char protocol[8];
    char host[255];
    int port;
    int fd;
} antd_proxy_t;

void init()
{
    use_raw_body();
}

void destroy()
{
    // Do nothing
}

/**
 * Check if the current request is a reverse proxy
 * return a proxy task if this is the case
*/
static int parse_proxy(antd_proxy_t *proxy, const char *buf)
{
    char *pattern = "^(https?)://([^:]+):([0-9]+)";
    char tmp[8];
    regmatch_t matches[4];
    int ret, size;

    (void)memset(tmp, 0, sizeof(tmp));

    ret = regex_match(pattern, buf, 4, matches);

    if (!ret)
    {
        ERROR("Unable to parse proxy: %s", buf);
        return -1;
    }
    size = matches[1].rm_eo - matches[1].rm_so > (int)sizeof(proxy->protocol) ? (int)sizeof(proxy->protocol) : matches[1].rm_eo - matches[1].rm_so;
    (void)memcpy(proxy->protocol, buf + matches[1].rm_so, size);

    // http proxy request
    size = matches[1].rm_eo - matches[2].rm_so < (int)sizeof(proxy->host) ? matches[2].rm_eo - matches[2].rm_so : (int)sizeof(proxy->host);
    (void)memcpy(proxy->host, buf + matches[2].rm_so, size);

    size = matches[2].rm_eo - matches[3].rm_so < (int)sizeof(tmp) ? matches[3].rm_eo - matches[3].rm_so : (int)sizeof(tmp);
    (void)memcpy(tmp, buf + matches[3].rm_so, size);

    proxy->port = atoi(tmp);

    return 0;
}

static void *proxy_monitor_data(void *data)
{
    antd_request_t *rq = (antd_request_t *)data;
    antd_client_t *proxy_cl = (antd_client_t *)dvalue(rq->request, "PROXY");
    antd_task_t *task = antd_create_task(NULL, data, NULL, rq->client->last_io);
    char buf[BUFFLEN];
    int sz;
    memset(buf, '\0', BUFFLEN);
    sz = read_buf(proxy_cl, buf, BUFFLEN);
    if (sz > 0)
    {
        antd_send(rq->client, buf, sz);
        if (rq->client->state > 0)
        {
            rq->client->state -= sz;
            if (rq->client->state <= 0)
            {
                (void)close(proxy_cl->sock);
                return task;
            }
        }
    }
    if (sz == 0 && rq->client->state < 0)
    {
        (void)close(proxy_cl->sock);
        return task;
    }

    if (sz < 0)
    {
        (void)close(proxy_cl->sock);
        return task;
    }
    task->handle = proxy_monitor_data;
    task->access_time = rq->client->last_io;
    antd_task_bind_event(task, rq->client->sock, 0, TASK_EVT_ON_WRITABLE | TASK_EVT_ON_READABLE);
    return task;
}

static void *proxy_monitor_header(void *data)
{
    antd_request_t *rq = (antd_request_t *)data;
    antd_client_t *proxy_cl = (antd_client_t *)dvalue(rq->request, "PROXY");
    antd_task_t *task = antd_create_task(NULL, data, NULL, rq->client->last_io);

    int ret, clen = -1;
    
    struct pollfd pfd[1];
    char buf[BUFFLEN];
    memset(pfd, 0, sizeof(struct pollfd));
    memset(buf, '\0', BUFFLEN);
    pfd[0].fd = proxy_cl->sock;
    pfd[0].events = POLLIN;
    // select
    antd_response_header_t rhd;
    rhd.header = dict();
    rhd.cookie = list_init();
    rhd.status = 200;
    regmatch_t matches[3];
    char *k;
    char *v;
    int len;
    ret = poll(pfd, 1, POLL_EVENT_TO);
    if (ret < 0)
    {
        ERROR("Unable to poll proxy fd %d", proxy_cl->sock);
        (void)close(proxy_cl->sock);
        return task;
    }
    if (ret > 0)
    {
        if (
            pfd[0].revents & POLLERR ||
            pfd[0].revents & POLLRDHUP ||
            pfd[0].revents & POLLHUP ||
            pfd[0].revents & POLLNVAL)
        {
            ERROR("Poll error event raised:");
            ERROR("POLLERR: %d", pfd[0].revents & POLLERR);
            ERROR("POLLRDHUP: %d", pfd[0].revents & POLLRDHUP);
            ERROR("POLLHUP: %d", pfd[0].revents & POLLHUP);
            ERROR("POLLNVAL: %d", pfd[0].revents & POLLNVAL);
            (void)close(proxy_cl->sock);
            return task;
        }

        if ((pfd[0].revents & POLLIN))
        {
            while (read_buf(proxy_cl, buf, BUFFLEN) > 0 && strcmp(buf, "\r\n") != 0)
            {
                trim(buf, '\n');
                trim(buf, '\r');
                if (regex_match("\\s*HTTP/1\\.1\\s+([0-9]{3})\\s+([a-zA-Z0-9]*)", buf, 3, matches))
                {
                    len = matches[1].rm_eo - matches[1].rm_so;
                    k = (char *)malloc(len);
                    memset(k, 0, len);
                    memcpy(k, buf + matches[1].rm_so, len);
                    rhd.status = atoi(k);
                    free(k);
                }
                else if (regex_match("^([a-zA-Z0-9\\-]+)\\s*:\\s*(.*)$", buf, 3, matches))
                {
                    len = matches[1].rm_eo - matches[1].rm_so;
                    k = (char *)malloc(len + 1);
                    memcpy(k, buf + matches[1].rm_so, len);
                    k[len] = '\0';
                    verify_header(k);
                    len = matches[2].rm_eo - matches[2].rm_so;
                    v = (char *)malloc(len + 1);
                    memcpy(v, buf + matches[2].rm_so, len);
                    v[len] = '\0';
                    if (strcmp(k, "Set-Cookie") == 0)
                    {
                        list_put_ptr(&rhd.cookie, v);
                    }
                    else
                    {
                        dput(rhd.header, k, v);
                    }
                    free(k);
                }
                else
                {
                    LOG("Ignore invalid header: %s", buf);
                }
            }
            v = dvalue(rhd.header, "Content-Length");
            if (v)
            {
                clen = atoi(v);
            }
            rq->client->state = clen;
            antd_send_header(rq->client, &rhd);
            antd_task_bind_event(task, rq->client->sock, 0,  TASK_EVT_ON_WRITABLE | TASK_EVT_ON_READABLE);
            task->handle = proxy_monitor_data;
            return task;
        }
    }

    task->handle = proxy_monitor_header;
    task->access_time = rq->client->last_io;
    return task;
}

void *handle(void *data)
{
    char *str = NULL;
    char buf[BUFFLEN];
    int ret, size, fd;
    chain_t it;
    antd_request_t *rq = (antd_request_t *)data;
    char *query = (char *)dvalue(rq->request, "REQUEST_QUERY");
    dictionary_t xheader = dvalue(rq->request, "REQUEST_HEADER");
    char *path = (char *)dvalue(rq->request, "RESOURCE_PATH");
    char *www = (char *)dvalue(rq->request, "SERVER_WWW_ROOT");
    char *method = (char *)dvalue(rq->request, "METHOD");
    char *clen_str = (char *)dvalue(xheader, "Content-Length");
    antd_proxy_t proxy;
    antd_client_t *proxy_cl = NULL;
    antd_task_t *task = antd_create_task(NULL, data, NULL, rq->client->last_io);
    (void)memset(buf, 0, BUFFLEN);
    if (ws_enable(rq->request) || !method)
    {
        ERROR("Unsupported method or Websocket");
        antd_error(rq->client, 503, "Service unavailable");
        return task;
    }

    str = __s("%s/%s", www, path);
    fd = open(str, O_RDONLY);
    free(str);
    if (fd == -1)
    {
        ERROR("Unable to open proxy file : %s: %s", path, strerror(errno));
        antd_error(rq->client, 500, "Proxy error");
        return task;
    }
    if (read(fd, buf, BUFFLEN - 1) < 0)
    {
        ERROR("Unable to read proxy file: %s: %s", path, strerror(errno));
        antd_error(rq->client, 500, "Proxy error");
        return task;
    }
    // parse the proxy configuration
    (void)memset(&proxy, 0, sizeof(antd_proxy_t));
    if (parse_proxy(&proxy, buf) == -1)
    {
        antd_error(rq->client, 500, "Proxy error");
        return task;
    }
    // check if this is https
    if (!EQU(proxy.protocol, "http"))
    {
        ERROR("Protocol unsupported: %s", proxy.protocol);
        antd_error(rq->client, 503, "Un supported protocol");
        return task;
    }
    proxy.fd = request_socket(ip_from_hostname(proxy.host), proxy.port);
    if (proxy.fd == -1)
    {
        ERROR("Unable to connect to proxy server: %s:%d", proxy.host, proxy.port);
        antd_error(rq->client, 503, "Service Unavailable");
        return task;
    }
    //set_nonblock(proxy.fd);
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = POLL_EVENT_TO*1000;
    if (setsockopt(proxy.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        ERROR("setsockopt failed:%s", strerror(errno));
        antd_error(rq->client, 500, "Internal proxy error");
        (void)close(proxy.fd);
        return task;
    }

    if (setsockopt(proxy.fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        ERROR("setsockopt failed:%s", strerror(errno));
        antd_error(rq->client, 500, "Internal proxy error");
        (void)close(proxy.fd);
        return task;
    }

    rq->client->z_level = ANTD_CNONE;
    proxy_cl = (antd_client_t *)malloc(sizeof(antd_client_t));
    proxy_cl->sock = proxy.fd;
    proxy_cl->ssl = NULL;
    proxy_cl->zstream = NULL;
    proxy_cl->z_level = ANTD_CNONE;
    proxy_cl->state = -1;
    dput(rq->request, "PROXY", proxy_cl);
    // send header
    str = __s("%s %s HTTP/1.1\r\n", method, query);
    size = strlen(str);
    ret = antd_send(proxy_cl, str, size);
    free(str);
    for_each_assoc(it, xheader)
    {
        str = __s("%s: %s\r\n", it->key, (char *)it->value);
        size = strlen(str);
        ret = antd_send(proxy_cl, str, size);
        free(str);
        if (ret != size)
        {
            ERROR("Unable to send headers to proxy sent %d expected %d", ret, size);
            antd_error(rq->client, 500, "Unable to send headers to proxy");
            (void)close(proxy_cl->sock);
            return task;
        }
    }
    (void)antd_send(proxy_cl, "\r\n", 2);
    // send raw body if any

    if (EQU(method, "POST"))
    {
        size = -1;
        if (clen_str)
            size = atoi(clen_str);
        if (size == -1)
        {
            ERROR("Content length header not found or invalid");
            antd_error(rq->client, 400, "Content length not provided");
            (void)close(proxy_cl->sock);
            return task;
        }
        do
        {
            ret = antd_recv_upto(rq->client, buf, BUFFLEN);
            if (ret < 0)
            {
                ERROR("Unable to read request content");
                antd_error(rq->client, 400, "Unable to read request content");
                (void)close(proxy_cl->sock);
                return task;
            }
            if (ret > 0)
            {
                size -= ret;
                if (antd_send(proxy_cl, buf, ret) != ret)
                {
                    ERROR("Unable to send request body to peer");
                    antd_error(rq->client, 500, "Unable to send request content via proxy");
                    (void)close(proxy_cl->sock);
                    return task;
                }
            }
        } while (size > 0);
    }
    // wait for data
    task->handle = proxy_monitor_header;
    task->access_time = rq->client->last_io;
    return task;
}