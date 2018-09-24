#include <iostream>
#include <string>
#include <regex>
#include <map>
#include <algorithm>
#include <io.h>

#include "mongoose.h"

#define MAX_PATH_SIZE 512

static struct mg_serve_http_opts opts;

static bool isExist(const std::string &file_Path)
{
#ifdef _WIN32
    return (0 == _access(file_Path.c_str(), 0));
#else
    return (0 == access(file_Path.c_str(), 0));
#endif
}

static bool getPair(const std::string &str, std::string &key, std::string &value)
{
    std::regex regex("-(.*?)=(.*)");
    std::smatch match;
    if (std::regex_match(str, match, regex)) {
        if (match.size() == 3) {
            key = match[1].str();
            value = match[2].str();

            std::transform(key.begin(), key.end(), key.begin(), ::toupper);
            std::cout << "key:" << key << ", value:" << value << '\n';

            return true;
        }
    }

    return false;
}

static void getUserSetting(int argc, const char* argv[], std::map<std::string, std::string> &argMap)
{
    for (int i = 0; i < argc; ++i) {
        std::string key;
        std::string value;
        if (getPair(argv[i], key, value)) {
            argMap[key] = value;
        }
    }
}

static void onHttpEvent(mg_connection *conn, int ev_type, void *ev_data)
{
    struct http_message *hm = (struct http_message *)ev_data;
    switch (ev_type) {
    case MG_EV_HTTP_REQUEST:
    {
        std::string method(hm->method.p, hm->method.len);
        std::string uri(hm->uri.p, hm->uri.len);
        std::string query_string(hm->query_string.p, hm->query_string.len);
        std::cout << "-------------------------------------------------------------------------------\n";
        std::cout << "method:" << method << "\n";
        std::cout << "uri:" << uri << "\n";
        std::cout << "query_string:" << query_string << "\n";
        std::cout << "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";

        if (uri == "/cocoyan.jpg") {
            mg_http_send_redirect(conn, 302, mg_mk_str("http://mrt.xesimg.com/user/h/def10002.png"), mg_mk_str(NULL));
        } else {
            mg_serve_http(conn, hm, opts);
        }
        break;
    }
    default:
        break;
    }
}

static void startServer(const std::string &root, const std::string &host, const std::string &port, const std::string &cert)
{
    mg_connection *connection = NULL;
    mg_mgr mgr;
    static struct mg_bind_opts bind_opts;
    
    char rootBuf[MAX_PATH_SIZE];
    char hostpostBuf[MAX_PATH_SIZE];
    char certBuf[MAX_PATH_SIZE];

    mg_mgr_init(&mgr, NULL);
    memset(&bind_opts, 0, sizeof(bind_opts));
    memset(rootBuf, 0, MAX_PATH_SIZE);
    memset(hostpostBuf, 0, MAX_PATH_SIZE);
    memset(certBuf, 0, MAX_PATH_SIZE);

    strcpy(rootBuf, root.c_str());
    if (host.size() > 0) {
        strcpy(hostpostBuf, host.c_str());
        strcat(hostpostBuf, ":");
    }
    strcat(hostpostBuf, port.c_str());
    strcpy(certBuf, cert.c_str());

    // If 'cert' is empty, starting a HTTP server, otherwise starting a HTTPS server.
    bool isHttpServer = cert.size() == 0;

    if (false == isHttpServer) {
        bind_opts.ssl_cert = certBuf;
    }

    connection = mg_bind_opt(&mgr, hostpostBuf, onHttpEvent, bind_opts);

    if (!connection) {
        std::cout << "mg_bind error.\n";
        return;
    }

    mg_set_protocol_http_websocket(connection);

    if (isHttpServer) {
        std::cout << "starting HTTP server at port:" << port << "\n";
    } else {
        std::cout << "starting HTTPS server at port:" << port << "\n";
    }

    opts.document_root = rootBuf;
    opts.enable_directory_listing = "yes";

    while (true) {
        mg_mgr_poll(&mgr, 500);
    }

    mg_mgr_free(&mgr);
}

// Start command:
// $path/LocalHttpServer.exe -root=web -port=9090 -cert=key.pem -type=https -host=127.0.0.1
int main(int argc, const char *argv[])
{
    std::map<std::string, std::string> argMap;
    getUserSetting(argc, argv, argMap);

    // Get port.
    std::string portStr = argMap["PORT"];
    int port = atoi(portStr.c_str());
    if (port < 1024 || port > 65535) {
        std::cout << "invalid port.\n";
        return -1;
    }

    // Get Host.
    std::string host = argMap["HOST"];

    // Get server type.
    std::string type = argMap["TYPE"];
    std::transform(type.begin(), type.end(), type.begin(), ::toupper);
    if (type != "HTTP" && type != "HTTPS") {
        std::cout << "invalid server type.\n";
        return -2;
    }

    // Get certificate.
    std::string cert;
    if (type == "HTTPS") {
        cert = argMap["CERT"];
        if (false == isExist(cert)) {
            std::cout << "invalid certificate.\n";
            return -3;
        }
    }

    // Get root.
    std::string root = argMap["ROOT"];
    if (false == isExist(root)) {
        std::cout << "invalid root path.\n";
        return -4;
    }

    startServer(root, host, portStr, cert);

    getchar();
    return 0;
}
