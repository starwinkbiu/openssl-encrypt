#include "Encrypt.h"
#include <iostream>
#include <string.h>

using namespace std;

void start(){
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


int main(int argc, char *argv[])
{
    start();
}
