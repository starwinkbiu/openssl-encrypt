#include "Encrypt.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>


string Encrypt::base64Encode(string data){
    string result;
    if(data.empty())
        return result;
    // 开始进行b64编码
    BIO* b64 = BIO_new(BIO_f_base64());
    if(!b64){
        cerr << "BIO_new(BIO_f_base64()) failed" << endl;
        return result;
    }
    BIO* mem = BIO_new(BIO_s_mem());
    if(!mem){
        cerr << "BIO_new(BIO_s_mem()) failed" << endl;
        BIO_free(b64);
        return result;
    }
    // 创建链条
    BIO_push(b64, mem);
    // 设置b64属性
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    // 输入明文
    int size = BIO_write(b64, &data[0], data.length());
    if(size <= 0){
        cerr << "BIO_write failed" << endl;
        BIO_free_all(b64);
        return result;
    }
    // 刷新
    BIO_flush(b64);
    // 获取mem内存指针
    BUF_MEM* buf;
    BIO_get_mem_ptr(mem, &buf);
    // 设置result空间
    result.reserve(buf->length);
    result.assign(buf->data, buf->length);
    // 释放空间
    BIO_free_all(b64);
    return result;
}

string Encrypt::base64Decode(string data){
    string result;
    BIO* b64 = BIO_new(BIO_f_base64());
    if(!b64){
        return result;
    }
    BIO* mem = BIO_new(BIO_s_mem());
    if(!mem){
        BIO_free(b64);
        return result;
    }
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    int size = BIO_write(mem, &data[0], data.size());
    if(size <= 0){
        BIO_free_all(b64);
        return result;
    }
    // 设置字符串长度，不能使用reverse，因为使用reverse并不会改变字符串空间长度，这样的话，当使用BIO_read读取完数据后，再使用resize(size)就会导致刚刚读取的数据被覆盖为0
    int resultsize = (int)((data.size() / 4) * 3) + 4;
    result.resize(resultsize);
    size = BIO_read(b64, &result[0], resultsize);
    result.resize(size);
    return result;
}

string Encrypt::md5Encode(string data){
    static unsigned char table[] = "0123456789abcdef";
    unsigned char hash[16];
    unsigned int md5Size = 0;
    string result;
    // 首先申请MD上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx){
        return result;
    }
    // 申请MD方法
    EVP_MD* md = EVP_MD_fetch(NULL, "MD5", NULL);
    if(!md){
        EVP_MD_CTX_free(ctx);
        return result;
    }
    // 初始化上下文
    if(!EVP_DigestInit_ex(ctx, md, NULL)){
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        return result;
    }
    // 计算摘要
    if(!EVP_DigestUpdate(ctx, &data[0], data.size())){
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        return result;
    }
    // 获取摘要
    if(!EVP_DigestFinal_ex(ctx, hash, &md5Size)){
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        string newres;
        return newres;
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    // 将二进制摘要变成字符串格式
    result.reserve(md5Size * 2);
    for(unsigned int i=0; i<md5Size; i++){
        result.push_back(table[ (hash[i] >> 4) & 0xf ]);
        result.push_back(table[ hash[i] & 0xf ]);
    }
    return result;
}

string Encrypt::getFileMd5(string filepath){
    string result;
    vector<string> hashList;
    fstream file(filepath.c_str(), ios::in | ios::binary);
    if(!file || !file.is_open()){
        return result;
    }
    // 读取内容
    char block[_DEF_BLOCK_SIZE] = { 0 };
    while(!file.eof()){
        string hash;
        file.read(block, _DEF_BLOCK_SIZE);
        if(file.gcount() < _DEF_BLOCK_SIZE){
            if(file.gcount() < 0){
                file.close();
                return result;
            }
            // 读取hash
            string tmp;
            tmp.assign(block, file.gcount());
            hash = md5Encode(tmp);
            hashList.push_back(hash);
            // 结束读取
            file.close();
            break;
        }
        // 读取hash
        string tmp;
        tmp.assign(block, _DEF_BLOCK_SIZE);
        hash = md5Encode(tmp);
        hashList.push_back(hash);
    }
    // 计算总hash
    string tmp;
    tmp.reserve(hashList.size() * 16 * 2);
    while(!hashList.empty()){
        string hash = hashList.back();
        hashList.pop_back();
        tmp.append(&hash[0], 32);
    }
    result = md5Encode(tmp);
    return result;
}
