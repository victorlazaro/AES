#include <iostream>
#include <sstream>
#include <iomanip>
#include "AES.h"

using namespace std;
typedef unsigned char byte;


vector<vector<byte>> input2 {vector<byte> {0x00, 0x11, 0x22, 0x33},
                             vector<byte> {0x44, 0x55, 0x66, 0x77},
                             vector<byte> {0x88, 0x99, 0xaa, 0xbb},
                             vector<byte> {0xcc, 0xdd, 0xee, 0xff}};
vector<vector<byte>> firstKey2 {vector<byte> {0x00, 0x01, 0x02, 0x03},
                                vector<byte> {0x04, 0x05, 0x06, 0x07},
                                vector<byte> {0x08, 0x09, 0x0a, 0x0b},
                                vector<byte> {0x0c, 0x0d, 0x0e, 0x0f}};
byte input[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
byte firstKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
byte test[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
vector<vector<byte>> test2 { vector<byte> {0x32, 0x43, 0xf6, 0xa8},
                             vector<byte> {0x88, 0x5a, 0x30, 0x8d},
                             vector<byte> {0x31, 0x31, 0x98, 0xa2},
                             vector<byte> {0xe0, 0x37, 0x07, 0x34}};

vector<vector<byte>> testKey2 {vector<byte> {0x2b, 0x7e, 0x15, 0x16},
                             vector<byte> {0x28, 0xae, 0xd2, 0xa6},
                             vector<byte> {0xab, 0xf7, 0x15, 0x88},
                             vector<byte> {0x09, 0xcf, 0x4f, 0x3c}};
byte testKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

int main() {

    AES aes = AES();
    //aes.cypher(test, testKey, 4, 10);
    aes.cypher(test2, testKey2, 4, 10);
//    aes.cypher(input, firstKey, 4, 10);

    return 0;
}