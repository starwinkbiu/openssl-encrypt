#include <string>

using namespace std;

#define _DEF_BLOCK_SIZE (1024)

class Encrypt{
public:
    static string base64Encode(string data);
    static string base64Decode(string data);
    static string md5Encode(string data);
    static string getFileMd5(string filepath);
};
