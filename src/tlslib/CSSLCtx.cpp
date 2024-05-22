#include <iostream>
#include <openssl/ssl.h>
#include "CSSLCtx.h"
#include "CSSL.h"

using namespace std;

CSSLCtx::CSSLCtx() : ctx_(NULL){

}
CSSLCtx::~CSSLCtx(){

}
// 设置上下文
void CSSLCtx::setContext(ssl_ctx_st* ctx){
    ctx_ = ctx;
}
// 创建服务器上下文
bool CSSLCtx::InitSSLServerContext(){
    if(ctx_){
        return false;
    }
    ssl_ctx_st* ctx;
    const SSL_METHOD* method;
    method = TLS_server_method();
    if(!method){
        return false;
    }
    ctx = SSL_CTX_new(method);
    if(!ctx){
        return false;
    }
    setContext(ctx);
    return true;
}
// 配置服务器上下文
void CSSLCtx::configServerContext(){
    // 使用证书和私钥
    if(!SSL_CTX_use_certificate_file(ctx_, "server.crt", SSL_FILETYPE_PEM)){
        cerr << "certificate load error" << endl;
        return;
    }else{
        cout << "certificate load success" << endl;
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx_, "server.key", SSL_FILETYPE_PEM)){
        cerr << "PrivateKey load error" << endl;
        return;
    }else{
        cout << "PrivateKey load success" << endl;
    }
    // 验证密钥
    if(!SSL_CTX_check_private_key(ctx_)){
        cerr << "PrivateKey is not match the certifacate" << endl;
        return;
    }else{
        cerr << "PrivateKey is match the certifacate" << endl;
    }
}
// 创建客户端上下文
bool CSSLCtx::InitSSLClientContext(){
    if(ctx_){
        return false;
    }
    ssl_ctx_st* ctx;
    const ssl_method_st* method;
    method = TLS_client_method();
    if(!method){
        cerr << "TLS_client_method failed" << endl;
        return false;
    }
    ctx = SSL_CTX_new(method);
    if(!ctx){
        cerr << "SSL_CTX_new failed" << endl;
        return false;
    }
    setContext(ctx);
    return true;
}
// 配置客户端上下文
void CSSLCtx::configClientContext(){
    // 验证服务器证书，首先加载CA证书（CA证书其实是服务器签名自己证书使用的另一组公私钥）
}
// 关闭上下文
void CSSLCtx::closeContext(){
    if(ctx_){
        SSL_CTX_free(ctx_);
    }
}
// 创建新的ssl连接
CSSL* CSSLCtx::NewSSL(int fd){
    CSSL* ssl_ = new CSSL();
    ssl_st* ssl;
    if(!ctx_ || !fd){
        return NULL;
    }
    ssl = SSL_new(ctx_);
    if(!ssl){
        cerr << "SSL_new failed" << endl;
        return NULL;
    }
    // 设置绑定套接字
    if(!SSL_set_fd(ssl, fd)){
        cerr << "SSL_set_fd failed" << endl;
        return NULL;
    }
    ssl_->SetSSL(ssl);
    return ssl_;
}

