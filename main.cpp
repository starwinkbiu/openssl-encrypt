#include "Encrypt.h"
#include <iostream>
#include <string.h>
#include <openssl/ssl.h>

#include <openssl/evp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/err.h>

#include "CSSLCtx.h"
#include "CSSL.h"

using namespace std;

#define _DEF_SERVER_PORT (27741)

ssl_ctx_st* TLS_CTX_client_init();
ssl_ctx_st* TLS_CTX_server_init();
ssl_st* newSSL(ssl_ctx_st* ctx, int sock);
void PrintCipher(ssl_st* ssl_);
void InitserverSSLContext(ssl_ctx_st* ctx);

void testEncrypt(){
    Encrypt encrypt;
    char s[10] = {0};
    memset(s, 0x63, sizeof s);
    string msg(s, sizeof s);
    string enData = encrypt.base64Encode(msg);
    cout << enData.c_str() << endl;
    string deData = encrypt.base64Decode(enData);
    cout << deData <<endl;
    string hash = encrypt.md5Encode(msg);
    cout << hash.c_str()<<endl;
    while(1){
        string filehash = encrypt.getFileMd5("./a.txt");
        cout << filehash.c_str() <<endl;
        timespec sp;
        sp.tv_sec = 1;
        sp.tv_nsec = 0;
        nanosleep(&sp, NULL);
    }
}

void server(){
    CSSLCtx ctx;
    // 初始化服务器上下文
    ctx.InitSSLServerContext();
    // 配置服务器上下文
    ctx.configServerContext();
    int opt = 1;
    int acceptSock = socket(AF_INET, SOCK_STREAM, 0);
    if(acceptSock == -1){
        cerr << "socket failed"<<endl;
        return;
    }
    if (setsockopt(acceptSock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            perror("setsockopt failed");
            close(acceptSock);
            exit(EXIT_FAILURE);
        }
    struct sockaddr_in addr;
    addr.sin_port = _DEF_SERVER_PORT;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    int err = bind(acceptSock, (sockaddr*)&addr, sizeof addr);
    if(err == -1){
        cerr << "bind failed"<<endl;
        close(acceptSock);
        return;
    }
    err = listen(acceptSock, 128);
    if(err == -1){
        cerr << "listen failed" <<endl;
        close(acceptSock);
        return;
    }
    // 开始接收连接请求
    while(1){
        cout << "start listening..." <<endl;
        sockaddr_in addr;
        unsigned int addrlen = sizeof addr;
        int clientSock = accept(acceptSock, (sockaddr*)&addr, &addrlen);
        // 添加ssl
        CSSL* ssl = ctx.NewSSL(clientSock);
        if(!ssl){
            continue;
        }else{
            cout << "set ssl success" <<endl;
        }
        if(!ssl->Accept()){
            cerr << "SSL_accept failed" << endl;
            continue;
        }
        cout << "accept [" << clientSock << "]..." <<endl;
        // 接收消息
        while(1){
            char buf[1204] = {0};
            int recvSize = recv(clientSock, buf, sizeof buf, 0);
            if(recvSize <=0){
                cout << "closed [" << clientSock << "]..." <<endl;
                close(clientSock);
                break;
            }
            cout << buf <<endl;
            int sendSize = send(clientSock, buf, recvSize, 0);
            if(sendSize <=0){
                close(clientSock);
                break;
            }
        }
    }
}

void client(){
    CSSL* ssl;
    CSSLCtx ctx;
    // 初始化客户端ssl上下文
    ctx.InitSSLClientContext();
    // 配置客户端上下文
    ctx.configClientContext();
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1){
        cerr << "socket failed"<<endl;
        return;
    }
    ssl = ctx.NewSSL(sock);
    if(!ssl){
        cerr << "ctx.NewSSL failed" <<endl;
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = _DEF_SERVER_PORT;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int err = connect(sock, (sockaddr*)&addr, sizeof addr);
    if(err == -1){
        cerr << "connect failed"<<endl;
        close(sock);
    }
    if(!ssl->Connect()){
        ERR_print_errors_fp(stderr);
        cerr << "SSL_connect failed" <<endl;
        return;
    }else{
        ssl->VerifyCertByCA("server.crt");
    }
    while(1){
        char buf[1024] = {0};
        char recvBuf[1024] = {0};
        cin >> buf;
        int sendSize = send(sock, buf, strlen(buf), 0);
        if(sendSize <= 0){
            close(sock);
            break;
        }
        int recvSize = recv(sock, recvBuf, sizeof recvBuf, 0);
        if(recvSize <=0){
            close(sock);
            break;
        }
        string msg(recvBuf, recvBuf);
        cout << msg.c_str() <<endl;
    }
}

ssl_ctx_st* TLS_CTX_server_init(){
    const SSL_METHOD* mtd;
    ssl_ctx_st* ctx;
    // 获取 tls 版本
    mtd = TLS_server_method();
    // 创建 ssl_ctx 上下文
    ctx = SSL_CTX_new(mtd);
    return ctx;
}

ssl_ctx_st* TLS_CTX_client_init(){
    const SSL_METHOD* mtd;
    ssl_ctx_st* ctx;
    // 获取 tls 版本
    mtd = TLS_client_method();
    // 创建 ssl_ctx 上下文
    ctx = SSL_CTX_new(mtd);
    return ctx;
}

void InitserverSSLContext(ssl_ctx_st* ctx){
    // 设置证书、私钥
    if(!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM)){
        cerr << "use certificate failed" <<endl;
        ERR_print_errors_fp(stderr);
        return;
    }else{
        cout << "Certificate load success" <<endl;
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)){
        cerr << "use privatekey failed" <<endl;
        ERR_print_errors_fp(stderr);
        return;
    }else{
        cout << "PrivateKey load success" <<endl;
    }
    // 验证
    if(SSL_CTX_check_private_key(ctx) != 1){
        cerr << "SSL_CTX_check_private_key failed" <<endl;
        ERR_print_errors_fp(stderr);
        return;
    }else{
        cout << "private key is match the certifacate" <<endl;
    }
}

void InitClientSSLClient(ssl_ctx_st* ctx){

}

ssl_st* newSSL(ssl_ctx_st* ctx, int sock){
    ssl_st* ssl;
    if(!ctx || !sock){
        return NULL;
    }
    // 创建ssl
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    return ssl;
}

void PrintCipher(ssl_st* ssl_){
    if(!ssl_){
        cerr << "ssl_ is NULL" <<endl;
    }
    cout << SSL_get_cipher(ssl_) << endl;
}

int main(int argc, char *argv[])
{
    if(argc == 1){
        server();
    }else{
        client();
    }
}
