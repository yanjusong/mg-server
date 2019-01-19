#include "mongoose.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#define ENTABLE_PRINT_HEADER

#define MAX_VALUE_LEN 256
#define MAX_PATH_SIZE 512

#define FREE_BUFFER(x) \
    if (x) free(x)

#define CHECK_MALLOC_AND_ERROR_GOTO(x, desc, end) \
    do { \
        if (!x) { \
                printf("malloc %s failed.", desc); \
                goto end; \
        } \
    } while (0)

static int isExist(const char *file_Path)
{
    int accessRet;
#ifdef _WIN32
    accessRet = (_access(file_Path, 0) == 0 ? 1 : -1);
#else
    accessRet = (access(file_Path, 0) == 0 ? 1 : -1);
#endif
    return accessRet;
}

static struct mg_serve_http_opts opts;

static void onHttpEvent(struct mg_connection *conn, int ev_type, void *ev_data)
{
    struct http_message *hm = (struct http_message *)ev_data;
    char *method_ = NULL;
    char *uri_    = NULL;
    char *query_  = NULL;
    char *name_   = NULL;
    char *value_  = NULL;
    int i;

    switch (ev_type) {
    case MG_EV_HTTP_REQUEST:
    {
        method_ = (char *)malloc(sizeof(char) *(hm->method.len + 1));
        uri_    = (char *)malloc(sizeof(char) *(hm->uri.len + 1));
        query_  = (char *)malloc(sizeof(char) *(hm->query_string.len + 1));

        CHECK_MALLOC_AND_ERROR_GOTO(method_, "method_", END);
        CHECK_MALLOC_AND_ERROR_GOTO(uri_, "uri_", END);
        CHECK_MALLOC_AND_ERROR_GOTO(query_, "query_", END);

        memcpy(method_, hm->method.p, hm->method.len);            method_[hm->method.len] = '\0';
        memcpy(uri_, hm->uri.p, hm->uri.len);                     uri_[hm->uri.len] = '\0';
        memcpy(query_, hm->query_string.p, hm->query_string.len); query_[hm->query_string.len] = '\0';

        struct mg_str *hname = hm->header_names;
        struct mg_str *hvalue = hm->header_values;

        printf("-------------------------------------------------------------------------------\n");
        printf("method:%s\n", method_);
        printf("uri:%s\n", uri_);
        printf("query_string:%s\n", query_);
        printf("from:%s:%d\n", inet_ntoa(conn->sa.sin.sin_addr), ntohs(conn->sa.sin.sin_port));
#ifdef ENTABLE_PRINT_HEADER
        name_  = (char *)malloc(sizeof(char) * 256);
        value_ = (char *)malloc(sizeof(char) * 1024);

        CHECK_MALLOC_AND_ERROR_GOTO(name_, "name_", END);
        CHECK_MALLOC_AND_ERROR_GOTO(value_, "value_", END);

        printf("****** header pairs: ******\n");
        for (i = 0; i < MG_MAX_HTTP_HEADERS; ++i) {
            memcpy(name_, hname[i].p, hname[i].len);     name_[hname[i].len] = '\0';
            memcpy(value_, hvalue[i].p, hvalue[i].len);  value_[hvalue[i].len] = '\0';
            if (strlen(name_) == 0) {
                break;
            } else {
                printf("%s:%s\n", name_, value_);
            }
        }
#endif
        printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

        // 模拟重定向
        if (strcmp(uri_, "/redirect") == 0) {
            mg_http_send_redirect(conn, 302, mg_mk_str("https://github.com/yanjusong"), mg_mk_str(NULL));
            printf("redirect to-> https://github.com/yanjusong\n");
        } else {
            mg_serve_http(conn, hm, opts);
        }
        break;
    }
    default:
        break;
    }

END:
    // free buffers
    FREE_BUFFER(method_);
    FREE_BUFFER(uri_);
    FREE_BUFFER(query_);
    FREE_BUFFER(name_);
    FREE_BUFFER(value_);
}

static void startServer(const char *root, const char *host, const char *port, const char *cert)
{
    struct mg_connection *connection = NULL;
    struct mg_mgr mgr;
    static struct mg_bind_opts bind_opts;

    char rootBuf[MAX_PATH_SIZE];
    char hostpostBuf[MAX_PATH_SIZE];
    char certBuf[MAX_PATH_SIZE];

    mg_mgr_init(&mgr, NULL);
    memset(&bind_opts, 0, sizeof(bind_opts));
    memset(rootBuf, 0, MAX_PATH_SIZE);
    memset(hostpostBuf, 0, MAX_PATH_SIZE);
    memset(certBuf, 0, MAX_PATH_SIZE);

    strcpy(rootBuf, root);
    if (host && strlen(host) > 0) {
        strcpy(hostpostBuf, host);
        strcat(hostpostBuf, ":");
    }
    strcat(hostpostBuf, port);
    strcpy(certBuf, cert);

    // If 'cert' is empty, starting a HTTP server, otherwise starting a HTTPS server.
    int isHTTPS = (strlen(cert) > 0 ? 1 : -1);

#ifdef MG_ENABLE_SSL
    if (isHTTPS > 0) {
        bind_opts.ssl_cert = certBuf;
    }
#else
    isHTTPS = -1;
#endif

    connection = mg_bind_opt(&mgr, hostpostBuf, onHttpEvent, bind_opts);

    if (!connection) {
        printf("mg_bind error.\n");
        return;
    }

    mg_set_protocol_http_websocket(connection);

    printf("starting %s server at port:%s, root:%s\n\n", (isHTTPS > 0 ? "HTTPS" : "HTTP"), port, root);

    opts.document_root = rootBuf;
    opts.enable_directory_listing = "yes";

    while (1) {
        mg_mgr_poll(&mgr, 500);
    }

    mg_mgr_free(&mgr);
}

#define KEY_NOT_MATCH -1
#define VALUE_NOT_MATCH -2

static int findValue(const char *str, const char *key, char *value, size_t vlen)
{
    size_t len, llen, rlen;
    char *pl = NULL;
    const char *p = NULL;
    int i = 0;
    int mid;
    int ret = VALUE_NOT_MATCH;

    p = str;
    len = strlen(p);

    if (len < 2 || p[0] != '-') {
        return KEY_NOT_MATCH;
    }

    p++;
    len--;

    mid = -1;
    for (i = len - 1; i >=0; --i) {
        if (p[i] == '=') {
            mid = i;
            break;
        } 
    }

    if (mid == -1) {
        return KEY_NOT_MATCH;
    }

    llen = mid;
    pl = (char *)malloc(sizeof(char) * (llen + 1));
    memcpy(pl, p, llen);
    pl[llen] = '\0';

    // find key
    if (strcmp(pl, key) == 0) {
        p = p + mid + 1;
        rlen = strlen(p);
        if (vlen >= rlen + 1) {
            memcpy(value, p, rlen);
            value[rlen] = '\0';
            ret = rlen;
        }
    }

    if (pl)
        free(pl);

    return ret;
}

static int findArgsValue(int argc, const char **argv, const char *key, char *value, size_t vlen)
{
    int i = 0;
    int ret = -1;

    for (i = 0; i < argc; ++i) {
        if (findValue(argv[i], key, value, vlen) > 0) {
            ret = 0;
            break;
        }
    }

    return ret;
}

// Start command:
// $path/mg-server.exe -root=web -port=9090 -cert=key.pem -type=https -host=127.0.0.1
int main(int argc, const char *argv[])
{
    char port_[MAX_VALUE_LEN];
    char root_[MAX_VALUE_LEN];
    char host_[MAX_VALUE_LEN];
    char type_[MAX_VALUE_LEN];
    char cert_[MAX_VALUE_LEN];

    memset(port_, 0, MAX_VALUE_LEN);
    memset(root_, 0, MAX_VALUE_LEN);
    memset(host_, 0, MAX_VALUE_LEN);
    memset(type_, 0, MAX_VALUE_LEN);
    memset(cert_, 0, MAX_VALUE_LEN);

    findArgsValue(argc, argv, "port", port_, MAX_VALUE_LEN);
    findArgsValue(argc, argv, "root", root_, MAX_VALUE_LEN);
    findArgsValue(argc, argv, "host", host_, MAX_VALUE_LEN);
    findArgsValue(argc, argv, "type", type_, MAX_VALUE_LEN);
    findArgsValue(argc, argv, "cert", cert_, MAX_VALUE_LEN);

    // 获取端口
    int port = atoi(port_);
    if ((port != 80 && port != 443 && port < 1024) || port > 65535) {
        printf("invalid port.\n");
        return -1;
    }

    // 获取服务器类型
    if (strcmp(type_, "http") != 0 && strcmp(type_, "https") != 0) {
        printf("invalid server type.\n");
        return -2;
    }

    // 检查证书
    if (strcmp(type_, "https") == 0) {
        if (isExist(cert_) < 0) {
            printf("invalid certificate.\n");
            return -3;
        }
    }

    // 获取挂载路径
    if (isExist(root_) < 0) {
        printf("invalid root path.\n");
        return -4;
    }

    startServer(root_, host_, port_, cert_);

    return 0;
}
