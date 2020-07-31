#if !defined(MISC_GUARDS_H)
#define MISC_GUARDS_H

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
    void release(void) { sock_fd_ = 0; }

private:
    int sock_fd_;
};

class BufGuard
{
public:
    BufGuard() : buf_(0) { }
    ~BufGuard() {
        if (buf_) {
            free(buf_);
            buf_ = 0;
        }
    }

    void guard(void * buf) { buf_ = buf; }

private:
    void * buf_ = 0;
};

#endif /* if !defined(MISC_GUARDS_H) */
