
class CSSL;

class CSSLCtx{
public:
    CSSLCtx();
    ~CSSLCtx();
    // 设置上下文
    void setContext(struct ssl_ctx_st* ctx);
    // 创建服务器上下文
    bool InitSSLServerContext();
    // 配置服务器上下文
    void configServerContext();
    // 创建客户端上下文
    bool InitSSLClientContext();
    // 配置客户端上下文
    void configClientContext();
    // 关闭上下文
    void closeContext();
    // 创建新的ssl连接
    CSSL* NewSSL(int fd);
private:
    struct ssl_ctx_st* ctx_;
};
