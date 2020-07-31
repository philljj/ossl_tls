#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ossl_tls.h"

static bool ossl_new_client_ctx(void);
static bool ossl_new_server_ctx(void);
static void ossl_get_err_str(char * errstr);
static void ossl_log_error(const char * what);
static bool get_pem_from_env(std::string & pem, const char * env_var);

static bool        tls_initialized = false;
static std::string tls_key_file;
static std::string tls_ca_file;
static SSL_CTX *   client_ctx = 0;
static SSL_CTX *   server_ctx = 0;
static bool        verify_peer = true;
static bool        verify_host = true;
const static int   server_verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
const static long  server_options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
                                  | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;



bool
tls::tls_init(bool ver_peer,
              bool ver_host)
{
    if (!tls_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_crypto_strings();

        if (!get_pem_from_env(tls_key_file, "TLS_KEY_FILE")) { return false; }
        if (!get_pem_from_env(tls_ca_file, "TLS_CA_FILE")) { return false; }
        if (!ossl_new_client_ctx()) { return false; }
        if (!ossl_new_server_ctx()) { return false; }

        verify_peer = ver_peer;
        verify_host = ver_host;

        tls_initialized = true;
    }

    return true;
}



bool
tls::tls_client_init(bool ver_peer,
                     bool ver_host)
{
    if (!tls_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_crypto_strings();

        if (!get_pem_from_env(tls_ca_file, "TLS_CA_FILE")) { return false; }
        if (!ossl_new_client_ctx()) { return false; }

        verify_peer = ver_peer;
        verify_host = ver_host;

        tls_initialized = true;
    }

    return true;
}



bool
tls::tls_server_init(void)
{
    if (!tls_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_crypto_strings();

        if (!get_pem_from_env(tls_key_file, "TLS_KEY_FILE")) { return false; }
        if (!get_pem_from_env(tls_ca_file, "TLS_CA_FILE")) { return false; }
        if (!ossl_new_server_ctx()) { return false; }

        tls_initialized = true;
    }

    return true;
}



void
tls::tls_cleanup(void)
{
    if (tls_initialized) {
        if (client_ctx) {
            SSL_CTX_free(client_ctx);
            client_ctx = 0;
        }

        if (server_ctx) {
            SSL_CTX_free(server_ctx);
            server_ctx = 0;
        }

        tls_initialized = false;
    }

    return;
}



static bool
ossl_new_client_ctx(void)
{
    if (tls_ca_file.empty()) {
        std::cerr << "error: ossl_new_client_ctx with no pem file" << std::endl;
        return false;
    }

    if (client_ctx) {
        std::cerr << "error: double initialization of client_ctx" << std::endl;
        return false;
    }

    const SSL_METHOD * method = TLSv1_2_client_method();
    char               errstr[256];

    client_ctx = SSL_CTX_new(method);

    if (!client_ctx) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_CTX_new failed: " << errstr << std::endl;
        return false;
    }

    SSL_CTX_set_mode(client_ctx, SSL_MODE_AUTO_RETRY);

    if (!SSL_CTX_load_verify_locations(client_ctx, tls_ca_file.c_str(), 0)) {
        ossl_get_err_str(errstr);
        std::cerr << "error: load verify failed: " << tls_ca_file << ": "
             << errstr << std::endl;
        return false;
    }

    return true;
}



static bool
ossl_new_server_ctx(void)
{
    if (tls_key_file.empty()) {
        std::cerr << "error: ossl_new_server_ctx with no key file" << std::endl;
        return false;
    }

    if (tls_ca_file.empty()) {
        std::cerr << "error: ossl_new_server_ctx with no ca file" << std::endl;
        return false;
    }

    if (server_ctx) {
        std::cerr << "error: double initialization of server_ctx" << std::endl;
        return false;
    }

    const SSL_METHOD * method = TLSv1_2_server_method();
    char               errstr[256];

    server_ctx = SSL_CTX_new(method);

    if (!server_ctx) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_CTX_new failed: " << errstr << std::endl;
        return false;
    }

    SSL_CTX_set_options(server_ctx, server_options);
    SSL_CTX_set_verify(server_ctx, server_verify, 0);

    if (SSL_CTX_use_certificate_chain_file(server_ctx,
                                           tls_ca_file.c_str()) <= 0) {
        ossl_get_err_str(errstr);
        std::cerr << "error: load verify failed: " << tls_ca_file << ": "
             << errstr << std::endl;
        return false;
    }

    SSL_CTX_set_client_CA_list(server_ctx,
                               SSL_load_client_CA_file(tls_ca_file.c_str()));

    if (SSL_CTX_use_PrivateKey_file(server_ctx, tls_key_file.c_str(),
                                    SSL_FILETYPE_PEM) <= 0) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_CTX_use_PrivateKey_file failed: " << tls_key_file
             << ": " << errstr << std::endl;
        return false;
    }

    return true;
}



static void
ossl_get_err_str(char * errstr)
{
    if (!errstr) { return; }

    unsigned long lerr = ERR_peek_last_error();

    ERR_error_string(lerr, errstr);

    return;
}



static void
ossl_log_error(const char *   what)
{
    int  ec;
    char errstr[256];

    while ((ec = ERR_get_error())) {
        ERR_error_string(ec, errstr);
        std::cerr << "error: " << what << ": " << errstr << std::endl;
    }

    return;
}



static bool
get_pem_from_env(std::string & pem_file,
                 const char *  env_var)
{
    const char * pem = getenv(env_var);

    if (!pem || !*pem) {
        std::cerr << "error: " << env_var << " environment variable not set"
                  << std::endl;
        return false;
    }

    struct stat sb;

    if (stat(pem, &sb) < 0) {
        int errsv = errno;
        std::cerr << "error: " << pem << ": " << strerror(errsv) << std::endl;
        return false;
    }

    if (sb.st_size == 0) {
        std::cerr << "error: file " << pem << " is empty" << std::endl;
        return false;
    }

    if (!S_ISREG(sb.st_mode)) {
        std::cerr << "error: file " << pem << " is not a regular file" << std::endl;
        return false;
    }

    pem_file = pem;

    std::cout << "info: found pem file " << pem_file << std::endl;

    return true;
}



bool
tls::ossl_connect(SSL *&         ssl,
                  int            sock_fd,
                  const char *   host)
{
    // Returns true if TLS handshake with server succeeds.
    //   On success ssl points to SSL object for session.
    //   On failure, session is cleaned up and ssl is zero.

    if (ssl) {
        // This shouldn't happen. We've stepped on an existing SSL session.
        std::cerr << "error: SSL object already exists" << std::endl;
        return false;
    }

    if (sock_fd <= 0) {
        std::cerr << "error: ssl_connect without socket handle" << std::endl;
        return false;
    }

    // Allocate SSL object, bind it to socket file descriptor, then
    // connect and pull peer cert.
    char errstr[256];

    ssl = SSL_new(client_ctx);

    if (!ssl) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_new failed: " << errstr << std::endl;
        return false;
    }

    OSSLConnGuard g_ssl(ssl);

    if (!SSL_set_fd(ssl, sock_fd)) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_set_fd failed: " << errstr << std::endl;
        return false;
    }

    int rc = SSL_connect(ssl);

    if (rc <= 0) {
        ossl_get_err_str(errstr);
        std::cerr << "error: ssl_connect failed: " << errstr << std::endl;
        return false;
    }

    g_ssl.needs_shutdown();

    X509 * peer_cert;

    peer_cert = SSL_get_peer_certificate(ssl);

    if (!peer_cert) {
        ossl_get_err_str(errstr);
        std::cerr << "error: could not get a peer cert: " << errstr << std::endl;
        return false;
    }

    g_ssl.guard_peer(peer_cert);

    if (verify_peer) {
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            ossl_get_err_str(errstr);
            std::cerr << "error: peer cert verify failed: " << errstr
                   << std::endl;
            return false;
        }
    }

    if (verify_host) {
        char peer_name[256];
        int  flags = 0;

        peer_name[0] = '\0';

        X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
                                  NID_commonName, peer_name, 256);

        rc = X509_check_host(peer_cert, host, strlen(host), flags, 0);

        if (rc > 0) {
            // Success. Maybe a message?
            //  cout << "info: host " << host << " and server "
            //         << peer_name << " match" << endl;
        }
        else if (rc == 0) {
            std::cerr << "error: host and server name don't match: "
                    << "expected: " << host << ", "
                    << "received: " << peer_name << std::endl;
            return false;
        }
        else if (rc == -1) {
            std::cerr << "error: X509_check_host failed: internal error" << std::endl;
            return false;
        }
        else {
            std::cerr << "error: X509_check_host failed: invalid input" << std::endl;
            return false;
        }
    }

    g_ssl.release_ssl_guard();

    return true;
}



bool
tls::ossl_accept(SSL *& ssl,
                 int    sock_fd)
{
    // Returns true if TLS handshake with client succeeds.
    //   On success ssl points to SSL object for session.
    //   On failure, session is cleaned up and ssl is zero.

    if (ssl) {
        // This shouldn't happen. We've stepped on an existing SSL session.
        std::cerr << "error: SSL object already exists" << std::endl;
        return false;
    }

    if (sock_fd <= 0) {
        std::cerr << "error: ssl_accept without socket handle" << std::endl;
        return false;
    }

    // Allocate SSL object, bind it to socket file descriptor, then accept.
    char errstr[256];

    if (!server_ctx) {
        std::cerr << "error: server_ctx not initialized" << std::endl;
        return false;
    }

    ssl = SSL_new(server_ctx);

    if (!ssl) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_new failed: " << errstr << std::endl;
        return false;
    }

    OSSLConnGuard g_ssl(ssl);

    if (!SSL_set_fd(ssl, sock_fd)) {
        ossl_get_err_str(errstr);
        std::cerr << "error: SSL_set_fd failed: " << errstr << std::endl;
        return false;
    }

    int rc = SSL_accept(ssl);

    if (rc <= 0) {
        ossl_get_err_str(errstr);
        std::cerr << "error: ssl_accept failed: " << errstr << std::endl;
        return false;
    }

    g_ssl.release_ssl_guard();

    return true;
}



void
tls::ossl_shutdown(SSL * ssl)
{
    if (!ssl) { return; }

    int rc = SSL_shutdown(ssl);

    switch (rc) {
    case 0:
        // The shutdown is not yet finished. Call SSL_shutdown()
        // for a second time, if a bidirectional shutdown shall
        // be performed.
        SSL_shutdown(ssl);
        break;
    case 1:
        // The shutdown was successfully completed. The
        // "close notify" alert was sent and the peer's
        // "close notify" alert was received.
        break;
    default:
        // The shutdown was not successful because a fatal error
        // occurred either at the protocol level or a connection
        // failure occurred. It can also occur if action is need
        // to continue the operation for non-blocking BIOs. Call
        // SSL_get_error(3) with the return value ret to find
        // out the reason.
        // TODO: error messages?
        break;
    }

    return;
}



void
tls::ossl_close(SSL *& ssl)
{
    if (!ssl) { return; }

    ossl_shutdown(ssl);
    ossl_safer_free(ssl);

    return;
}



int
tls::ossl_send(SSL *&         w_ssl,
               const void *   v_buf,
               size_t         buf_len)
{
    // This method does not return until buf_len has been sent,
    // or an error has occurred. w_ssl may be freed and set to 0
    // on error.
    if (!w_ssl) { return -1; }

    const u_char * buf = static_cast<const u_char *>(v_buf);
    int            tcs = 0;
    size_t         w_len = 0;
    size_t         w_total = 0;

    ERR_clear_error();

    while (buf_len != 0) {
        w_len = buf_len < TLSPP_MSG_LEN ? buf_len : TLSPP_MSG_LEN;

        tcs = SSL_write(w_ssl, buf, w_len);
        if (tcs <= 0) { break; }

        buf += tcs;
        buf_len -= tcs;
        w_total += tcs;
    }

    if (tcs > 0 && buf_len == 0) {
        return w_total;
    }

    int errsv;

    switch (SSL_get_error(w_ssl, tcs)) {
    case SSL_ERROR_NONE:
        // This shouldn't happen.
        std::cerr << "error: SSL_write returned "
               << tcs << " was expecting " << w_len
               << ", " << w_total
               << " bytes transferred." << std::endl;

        return w_total;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        // Let calling function decide whether to retry.
        return w_total;

    case SSL_ERROR_ZERO_RETURN:
        // TLS connection has been closed. We should shutdown.
        ossl_close(w_ssl);
        return 0;

    case SSL_ERROR_SYSCALL:
        // Note that SSL_shutdown() must not be called if a previous
        // fatal error has occurred on a connection i.e. if
        // SSL_get_error() has returned SSL_ERROR_SYSCALL or SSL_ERROR_SSL.
        errsv = errno;
        std::cerr << "error: SSL_write failed: SSL_ERROR_SYSCALL: " << strerror(errsv) << std::endl;
        break;

    case SSL_ERROR_SSL:
        ossl_log_error("SSL_write failed");
        break;

    default:
        std::cerr << "error: SSL_write failed: unknown error" << std::endl;
        break;
    }

    ossl_safer_free(w_ssl);

    return -1;
}



int
tls::ossl_recv(SSL *&  r_ssl,
               void *  v_buf,
               size_t  buf_len)
{
    // This method does not return until buf_len has been received,
    // or an error has occurred. r_ssl may be freed and set to 0
    // on error.
    if (!r_ssl) { return -1; }

    u_char * buf = static_cast<u_char *>(v_buf);
    int      tcs = 0;
    size_t   r_len = 0;
    size_t   r_total = 0;

    ERR_clear_error();

    while (buf_len != 0) {
        r_len = buf_len < TLSPP_MSG_LEN ? buf_len : TLSPP_MSG_LEN;

        tcs = SSL_read(r_ssl, buf, r_len);
        if (tcs <= 0) { break; }

        buf += tcs;
        buf_len -= tcs;
        r_total += tcs;

        if (SSL_pending(r_ssl) == 0) {
            // We got everything there was to read for now.
            return r_total;
        }
    }

    if (tcs > 0 && buf_len == 0) {
        return r_total;
    }

    int errsv = errno;

    switch (SSL_get_error(r_ssl, tcs)) {
    case SSL_ERROR_NONE:
        // This shouldn't happen.
        std::cerr << "error: SSL_read returned "
               << tcs << " was expecting " << r_len
               << ", " << r_total
               << " bytes transferred." << std::endl;

        return r_total;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        // Let calling function decide whether to retry.
        return r_total;

    case SSL_ERROR_ZERO_RETURN:
        // TLS connection has been closed. We should shutdown.
        ossl_close(r_ssl);
        return 0;

    case SSL_ERROR_SYSCALL:
        // Note that SSL_shutdown() must not be called if a previous
        // fatal error has occurred on a connection i.e. if
        // SSL_get_error() has returned SSL_ERROR_SYSCALL or SSL_ERROR_SSL.
        std::cerr << "error: SSL_read failed: SSL_ERROR_SYSCALL: " << strerror(errsv) << std::endl;
        break;

    case SSL_ERROR_SSL:
        ossl_log_error("SSL_read failed");
        break;

    default:
        std::cerr << "error: SSL_read failed: unknown error" << std::endl;
        break;
    }

    ossl_safer_free(r_ssl);

    return -1;
}



void
tls::ossl_safer_free(SSL *& ssl)
{
    if (ssl) {
        SSL_free(ssl);
        ssl = 0;
    }

    return;
}
