#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include "CSSL.h"

using namespace std;

CSSL::CSSL() : ssl_(NULL){

}
CSSL::~CSSL(){

}
// 设置ssl_st
void CSSL::SetSSL(struct ssl_st* ssl){
    this->ssl_ = ssl;
}
// 查看是否为空
bool CSSL::IsEmpty(){
    return ssl_ == 0;
}
// 接收客户端套接字连接(用于服务器)
bool CSSL::Accept(){
    if(!ssl_){
        return false;
    }
    if(SSL_accept(ssl_) <= 0){
        cerr << "SSL_accept failed" << endl;
        return false;
    }
    // 打印对方使用的tls加密方法
    PrintCipher();
    return true;
}
// 连接服务器
bool CSSL::Connect(){
    if(!ssl_){
        return false;
    }
    if(SSL_connect(ssl_) <= 0){
        cerr << "SSL_connect failed" << endl;
        return false;
    }
    // 打印对方使用的tls加密方法
    PrintCipher();
    PrintPeerCertInfo();
    PrintCertIssuerInfo();
    return true;
}
// 打印加密方法
void CSSL::PrintCipher(){
    if(!ssl_){
        return;
    }
    cout << SSL_get_cipher(ssl_) << endl;
}
// 关闭ssl
void CSSL::CloseSSL(){
    if(ssl_){
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
}
// 打印证书信息
void CSSL::PrintPeerCertInfo(){
    if(!ssl_){
        return;
    }
    X509* cert = SSL_get_peer_certificate(ssl_);
    if(!cert){
        return;
    }
    X509_NAME* name = X509_get_subject_name(cert);
    if(!name){
        return;
    }
    cout << X509_NAME_oneline(name, NULL, 0) << endl;
    X509_free(cert);
    X509_NAME_free(name);
}
// 打印证书颁发着信息
void CSSL::PrintCertIssuerInfo(){
    if(!ssl_){
        return;
    }
    X509* cert = SSL_get_peer_certificate(ssl_);
    if(!cert){
        return;
    }
    X509_NAME* name = X509_get_issuer_name(cert);
    if(!name){
        return;
    }
    cout << X509_NAME_oneline(name, NULL, 0) << endl;
    X509_free(cert);
    X509_NAME_free(name);
}
// 验证证书
bool CSSL::VerifyCertByCA(const char* CAfile){
    // 申请STORE存储CA证书
    X509_STORE* CAcert = X509_STORE_new();
    if(!CAcert){
        cerr << "X509_STORE_new failed" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    // 读取CA证书到STORE
    if(!X509_STORE_load_locations(CAcert, "server.crt", NULL)){
        cerr << "X509_STORE_load_locations failed" << endl;
        ERR_print_errors_fp(stderr);
        X509_STORE_free(CAcert);
        return false;
    }
    // 创建STORE上下文
    X509_STORE_CTX* ctx;
    ctx = X509_STORE_CTX_new();
    if(!ctx){
        cerr << "X509_STORE_CTX_new failed" << endl;
        ERR_print_errors_fp(stderr);
        X509_STORE_free(CAcert);
        return false;
    }
    // 获取服务器证书
    X509* cert = SSL_get_peer_certificate(ssl_);
    if(!cert){
        cerr << "SSL_get_peer_certificate failed" << endl;
        ERR_print_errors_fp(stderr);
        X509_STORE_free(CAcert);
        X509_STORE_CTX_free(ctx);
        X509_free(cert);
        return false;
    }
    // 初始化上下文
    if(!X509_STORE_CTX_init(ctx, CAcert, cert, NULL)){
        cerr << "X509_STORE_CTX_init failed" << endl;
        ERR_print_errors_fp(stderr);
        X509_STORE_free(CAcert);
        X509_STORE_CTX_free(ctx);
        X509_free(cert);
        return false;
    }
    // 使用STORE_CONTEXT验证服务器证书
    if(!X509_verify_cert(ctx)){
        cout << "certifacate verified failed: " << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)) << endl;
        X509_STORE_free(CAcert);
        X509_STORE_CTX_free(ctx);
        X509_free(cert);
        return false;
    }else{
        cout << "certifacate verified success" << endl;
    }
    // 释放CA证书和STORE上下文
    X509_STORE_free(CAcert);
    X509_STORE_CTX_free(ctx);
    X509_free(cert);
    return true;
}
