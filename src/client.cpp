#include <iostream>

#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ossl_tls.h"

class SockGuard
{
    public:
    SockGuard() : sock_fd_(0) { }
    ~SockGuard() {
        if (sock_fd_) {
            std::cout << "info: closing sock: " << sock_fd_ << std::endl;
            close(sock_fd_);
            sock_fd_ = 0;
        }
    }

    void guard(int sock_fd) { sock_fd_ = sock_fd; }

    int sock_fd_;
};

static int  new_client_socket(const char * host, const char * port);
static void print_usage_and_die(void) __attribute__((__noreturn__));

const char * rush_lyrics = "My uncle has a country place\n"
                           "That no one knows about\n"
                           "He says it used to be a farm\n"
                           "Before the Motor Law\n"
                           "And now on Sundays, I elude the eyes\n"
                           "And hop the turbine freight\n"
                           "To far outside the wire where my\n"
                           "White-haired uncle waits\n";



int
main(int    argc,
     char * argv[])
{
    if (argc != 3 && argc != 4) {
        print_usage_and_die();
    }

    const char * host = argv[1];
    const char * port = argv[2];
    const char * send_msg = rush_lyrics;

    if (argc == 4) {
        send_msg = argv[3];
    }

    int sock_fd = new_client_socket(host, port);

    if (sock_fd <= 0) {
        print_usage_and_die();
    }

    SockGuard g_client;
    g_client.guard(sock_fd);

    if (!tls::tls_client_init(true, true)) {
        std::cerr << "error: tls_init failed" << std::endl;
        return EXIT_FAILURE;
    }

    SSL * ssl = 0;

    if (!tls::ossl_connect(ssl, sock_fd, host)) {
        std::cerr << "error: ossl_connect failed" << std::endl;
        return EXIT_FAILURE;
    }

    tls::OSSLConnGuard g_ssl(ssl);
    g_ssl.needs_shutdown();

    int w_len = tls::ossl_send(ssl, send_msg, strlen(send_msg));

    if (w_len == 0) {
        std::cerr << "info: ossl_send: connection closed" << std::endl;
        return EXIT_FAILURE;
    }
    else if (w_len < 0) {
        std::cerr << "error: ossl_send failed" << std::endl;
        return EXIT_FAILURE;
    }

    char reply_msg[257];

    memset(reply_msg, '\0', sizeof(reply_msg));

    int r_len = tls::ossl_recv(ssl, reply_msg, 256);

    if (r_len == 0) {
        std::cerr << "info: ossl_recv: connection closed"
                  << std::endl;
        return EXIT_FAILURE;
    }
    else if (r_len < 0) {
        std::cerr << "error: ossl_recv failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "info: server sent this reply:" << std::endl
              << reply_msg << std::endl;

    return EXIT_SUCCESS;
}



static int
new_client_socket(const char * host,
                  const char * port)
{
    struct hostent *server = gethostbyname(host);

    if (server == NULL) {
        // Sometimes fprintf is more concise.
        fprintf(stderr, "error: gethostbyname(host) failed. host=%s,"
                " h_errno=%d - %s\n", host, h_errno, hstrerror(h_errno));
        return -1;
    }

    struct sockaddr_in serv_addr;

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    int port_num = atoi(port);

    serv_addr.sin_port = htons(port_num);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd < 0) {
        int errnum = errno;
        fprintf(stderr, "error: open socket failed. sock_fd=%d, err=%d - %s\n",
                sock_fd, errnum, strerror(errnum));
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))
        < 0) {
        int errnum = errno;
        fprintf(stderr,
                "failed to connect to host %s port %u, errno=%d - %s\n",
                host, port_num, errnum, strerror(errnum));
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}



static void
print_usage_and_die(void)
{
    std::cerr << "usage:" << std::endl;
    std::cerr << "  tls_client <hostname> <port>" << std::endl;

    exit(EXIT_FAILURE);
}
