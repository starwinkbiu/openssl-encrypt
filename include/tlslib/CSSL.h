



class CSSL{
public:
    CSSL();
    ~CSSL();
    // 设置ssl_st
    void SetSSL(struct ssl_st* ssl);
    // 查看是否为空
    bool IsEmpty();
    // 接收客户端套接字连接(用于服务器)
    bool Accept();
    // 连接服务器
    bool Connect();
    // 打印加密方法
    void PrintCipher();
    // 关闭ssl
    void CloseSSL();
    // 打印证书信息
    void PrintPeerCertInfo();
    // 打印证书颁发着信息
    void PrintCertIssuerInfo();
    // 验证证书
    bool VerifyCertByCA(const char* CAfile);
private:
    struct ssl_st* ssl_;
};
