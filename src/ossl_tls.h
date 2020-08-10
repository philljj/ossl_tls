//-*-C++-*-
#if !defined(TLSPP_H_)
#define TLSPP_H_
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#define TLSPP_MSG_LEN       (16 * 1024)
#define MAX_SYS_ERR_MSG_LEN (2048)

namespace tls {

    bool  tls_init(bool ver_peer, bool ver_host, const char *req_cipher_list);
    bool  tls_client_init(bool ver_peer, bool ver_host);
    bool  tls_server_init(const char * req_cipher_list);
    void  tls_cleanup(void);
    bool  ossl_connect(SSL *&ssl, int sock_fd,
                       const char * host);
    bool  ossl_accept(SSL *&ssl, int sock_fd);
    void  ossl_shutdown(SSL *ssl);
    void  ossl_close(SSL *&ssl);
    void  ossl_safer_free(SSL *& ssl);
    int   ossl_send(SSL *&ssl, const void * v_buf,
                    size_t buf_len);
    int   ossl_recv(SSL *&ssl, void * v_buf,
                    size_t buf_len);

    class OSSLConnGuard
    {
    public:
        explicit OSSLConnGuard(SSL *& ssl)
            : ssl_(ssl), peer_(0), guarding_(true), needs_shutdown_(false)
        {
        }

        ~OSSLConnGuard()
        {
            if (peer_) {
                X509_free(peer_);
                peer_ = 0;
            }

            if (ssl_ && guarding_) {
                if (needs_shutdown_) {
                    tls::ossl_shutdown(ssl_);
                    needs_shutdown_ = false;
                }

                ossl_safer_free(ssl_);
            }
        }

        void guard_peer(X509 * peer) { peer_ = peer; }
        void needs_shutdown(void) { needs_shutdown_ = true; }

        void release_ssl_guard(void)
        {
            guarding_ = false;
            needs_shutdown_ = false;
            return;
        }

    private:
        SSL *& ssl_;
        X509 * peer_;
        bool   guarding_;
        bool   needs_shutdown_;
    };
}

#endif /* !defined(TLSPP_H_) */
