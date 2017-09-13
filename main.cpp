#include <iostream>
#include "AES.h"

vector<vector<byte>> input {vector<byte> {0x00, 0x11, 0x22, 0x33},
                             vector<byte> {0x44, 0x55, 0x66, 0x77},
                             vector<byte> {0x88, 0x99, 0xaa, 0xbb},
                             vector<byte> {0xcc, 0xdd, 0xee, 0xff}};
vector<vector<byte>> key128 {vector<byte> {0x00, 0x01, 0x02, 0x03},
                             vector<byte> {0x04, 0x05, 0x06, 0x07},
                             vector<byte> {0x08, 0x09, 0x0a, 0x0b},
                             vector<byte> {0x0c, 0x0d, 0x0e, 0x0f}};

vector<vector<byte>> key192 {vector<byte> {0x00, 0x01, 0x02, 0x03},
                             vector<byte> {0x04, 0x05, 0x06, 0x07},
                             vector<byte> {0x08, 0x09, 0x0a, 0x0b},
                             vector<byte> {0x0c, 0x0d, 0x0e, 0x0f},
                             vector<byte> {0x10, 0x11, 0x12, 0x13},
                             vector<byte> {0x14, 0x15, 0x16, 0x17}};

vector<vector<byte>> key256 {vector<byte> {0x00, 0x01, 0x02, 0x03},
                             vector<byte> {0x04, 0x05, 0x06, 0x07},
                             vector<byte> {0x08, 0x09, 0x0a, 0x0b},
                             vector<byte> {0x0c, 0x0d, 0x0e, 0x0f},
                             vector<byte> {0x10, 0x11, 0x12, 0x13},
                             vector<byte> {0x14, 0x15, 0x16, 0x17},
                             vector<byte> {0x18, 0x19, 0x1a, 0x1b},
                             vector<byte> {0x1c, 0x1d, 0x1e, 0x1f}};

vector<vector<byte>> test { vector<byte> {0x32, 0x43, 0xf6, 0xa8},
                             vector<byte> {0x88, 0x5a, 0x30, 0x8d},
                             vector<byte> {0x31, 0x31, 0x98, 0xa2},
                             vector<byte> {0xe0, 0x37, 0x07, 0x34}};

vector<vector<byte>> testKey {vector<byte> {0x2b, 0x7e, 0x15, 0x16},
                             vector<byte> {0x28, 0xae, 0xd2, 0xa6},
                             vector<byte> {0xab, 0xf7, 0x15, 0x88},
                             vector<byte> {0x09, 0xcf, 0x4f, 0x3c}};

int main() {

    AES aes = AES();
//    aes.cypher(test, testKey, 4, 10);
    aes.cypher(input, key128, 4, 10);
    aes.invCypher(aes.getState(), key128, 4, 10);
    aes.cypher(input, key192, 6, 12);
    aes.invCypher(aes.getState(), key192, 6, 12);
    aes.cypher(input, key256, 8, 14);
    aes.invCypher(aes.getState(), key256, 8, 14);

    return 0;
}
