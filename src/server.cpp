#include <iostream>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ossl_tls.h"
#include "misc_guards.h"

static void  print_usage_and_die(void) __attribute__((__noreturn__));
static int   new_server_socket(int port);
const char * server_reply = "Thank you, please come again.\n";



int
main(int    argc,
     char * argv[])
{
    if (argc != 2 && argc != 3) {
        print_usage_and_die();
    }

    int port = atoi(argv[1]);

    if (port <= 0) {
        print_usage_and_die();
    }

    int sock_fd = new_server_socket(port);

    if (sock_fd <= 0) {
        print_usage_and_die();
    }

    const char * cipher_list = 0;

    if (argc == 3) {
        cipher_list = argv[2];
    }

    SockGuard g_server;
    g_server.guard(sock_fd);

    if (!tls::tls_init(true, true, cipher_list)) {
        std::cerr << "error: tls_init failed" << std::endl;
        return EXIT_FAILURE;
    }

    char * msg_buf = static_cast<char *>(malloc(TLSPP_MSG_LEN + 1));

    if (!msg_buf) {
        std::cerr << "error: failed to allocate msg_buf" << std::endl;
        return EXIT_FAILURE;
    }

    BufGuard g_buf;
    g_buf.guard(msg_buf);

    for (;;) {
        struct sockaddr_in addr;
        uint               len = sizeof(addr);
        SSL *              ssl = 0;

        int client = accept(sock_fd, (struct sockaddr*)&addr, &len);

        if (client < 0) {
            std::cerr << "error: accept( failed" << std::endl;
            break;
        }

        SockGuard g_accept;
        g_accept.guard(client);

        if (tls::ossl_accept(ssl, client)) {
            std::cout << "info: ossl_accept success" << std::endl;
        }
        else {
            std::cerr << "error: ossl_accept failed" << std::endl;
            continue;
        }

        tls::OSSLConnGuard g_ssl(ssl);
        g_ssl.needs_shutdown();

        memset(msg_buf, '\0', TLSPP_MSG_LEN + 1);

        int r_len = tls::ossl_recv(ssl, msg_buf, TLSPP_MSG_LEN);

        if (r_len == 0) {
            std::cerr << "info: ossl_recv: connection closed"
                      << std::endl;
            continue;
        }
        else if (r_len < 0) {
            std::cerr << "error: ossl_recv failed" << std::endl;
            continue;
        }

        std::cout << "info: client sent this message:" << std::endl
                  << msg_buf << std::endl;

        if (memcmp(msg_buf, "stop", strlen("stop")) == 0) {
            break;
        }
        else {
            int w_len = tls::ossl_send(ssl, server_reply, strlen(server_reply));

            if (w_len == 0) {
                std::cerr << "info: ossl_send: connection closed"
                          << std::endl;
                continue;
            }
            else if (w_len < 0) {
                std::cerr << "error: ossl_send failed" << std::endl;
                continue;
            }
        }
    }

    return EXIT_SUCCESS;
}



static void
print_usage_and_die(void)
{
    std::cerr << "usage:" << std::endl
              << "  tls_server <port> [cipher list]" << std::endl
              << std::endl
              << "notes:" << std::endl
              << "  cipher list defaults to \"HIGH\"" << std::endl;

    exit(EXIT_FAILURE);
}



static int
new_server_socket(int port)
{
    int                sock_fd;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd < 0) {
        // Sometimes fprintf is more concise.
        int errnum = errno;
        fprintf(stderr, "error: open socket failed. sock_fd=%d, err=%d - %s\n",
                sock_fd, errnum, strerror(errnum));
        return -1;
    }

    SockGuard g_server;
    g_server.guard(sock_fd);

    if (bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "error: bind socket failed" << std::endl;
        return -1;
    }

    if (listen(sock_fd, 1) < 0) {
        int errnum = errno;
        fprintf(stderr, "error: listen socket failed. port=%d, err=%d - %s\n",
                port, errnum, strerror(errnum));
        return -1;
    }

    g_server.release();

    return sock_fd;
}
