//
// Created by Victor Lazaro on 9/8/17.
//

#include <cstdlib>
#include <printf.h>
#include <iostream>
#include <vector>
#include "AES.h"

AES::AES() = default;

void AES::addRoundKey(int startIndex) {

    for (auto i = 0; i < 4; i++)
    {
        for (auto j = 0; j < 4; j++)
        {
            state[i][j] = ffAdd(expandedKey[i + startIndex][j], state[i][j]);
        }
    }

}

void AES::printMatrix(vector<vector<byte>> matrix) {

    for (auto m : matrix)
    {
        for (auto n : m)
        {
            printf("%.2x ", n);
        }
        cout << "\n";

    }
    cout << "\n";

}

void AES::subBytes() {

    for (auto i = 0; i < 4; i++)
    {
        for (auto j = 0; j < 4; j++)
        {
            state[i][j] = s[(state[i][j] >> 4) & 0x0F][state[i][j] & 0x0F];
        }
    }

}

void AES::shiftRows() {


    vector<vector<byte>> transposed = transpose(state);

    for (auto i = 1; i < 4; i++)
    {
        for (int j = 0; j < i; j++)
        {
            rotWord(transposed[i]);
        }
    }

    state = transpose(transposed);
}


void AES::mixColumns() {


    vector<vector<byte>> newState = state;


    for (auto i = 0; i < 4; i++) // fixed rows
    {
        for (auto j = 0; j < 4; j++) // state columns
        {
            for (auto k = 0; k < 4; k++) // state rows
            {
                newState[i][j] = ffAdd(ffMultiply(fixed[i][k], state[k][j]), newState[i][j]);
                printf("%.2x\n", newState[i][j]);
            }
        }
    }
    state = newState;
}

byte AES::ffAdd(byte a, byte b) {
    return a ^ b;
}

byte AES::xtime(byte a) {

    unsigned int c = a << 1;
    if (c & 0x100)
    {
        c ^= 0x11b;
    }
    return (byte) c;
}

byte AES::ffMultiply(byte a, byte b) {

    byte sum = 0x00;

    vector<byte> temp;
    temp.push_back(a);

    for (auto i = 1; i < 8; i++)
    {
        temp.push_back(xtime(temp[i-1]));
    }

    for (int i = 0; i < 8; i++)
    {
        if (b & 0x01)
        {
            sum = ffAdd(temp[i], sum);
        }
        b >>= 1;
    }
    return sum;

}


void AES::subWord(vector<byte>& word) {

    for (int i = 0; i < 4; i++)
        word[i] = s[(word[i] >> 4) & 0x0F][word[i] & 0x0F];

}

void AES::cypher(vector<vector<byte>> input, vector<vector<byte>> inputKey, int nk, int nr) {


//    printMatrix(input);
    state = input;
    printMatrix(state);
    int wordCount = Nb * (nr + 1);
    expandedKey = keySchedule(inputKey, wordCount, nk);
    addRoundKey(0);
    printMatrix(state);
    for (int i = 1; i < nr; i++)
    {
        subBytes();
        printMatrix(state);
        shiftRows();
        printMatrix(state);
//        mixColumns();
//        printStateMatrix();
//        addRoundKey(i * 4);
//        printStateMatrix();
    }
//
//    subBytes();
//    shiftRows();
//    printStateMatrix();
//    addRoundKey(40);


}


void AES::invSubBytes() {

}

void AES::invShiftRows() {

}

void AES::invMixColumns() {

}

vector<vector<byte>> AES::keySchedule(byte** key, int wordCount, int nk) {
    vector<vector<byte>> keys;

    for (auto i = 0; i < 4; i++)
    {
        vector<byte> temp;
        keys.push_back(temp);
        for (auto j = 0; j < 4; j++)
        {
            keys[i].push_back(key[j][i]);
        }

    }

    int i = nk;

    vector<byte> temp;
    byte constant = 0x01;
    while (i < wordCount)
    {
        temp = keys[i-1];
        if (i % nk == 0)
        {
            rotWord(temp);
            subWord(temp);
            vector<byte> roundConstant {constant, 0x00, 0x00, 0x00};
            temp = wordXor(temp, roundConstant);
            constant = ffMultiply(constant, 2);
        }
        else if (nk > 6 && i % nk == 4)
        {
            subWord(temp);
        }
        keys.push_back(wordXor(keys[i-nk], temp));
        i++;
    }
    return keys;
}

void AES::rotWord(vector<byte>& word) {
    byte temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;

}

vector<byte> AES::wordXor(vector<byte> &word, vector<byte> &temp) {

    vector<byte> result;
    for (int i = 0; i < Nb; i++)
    {
        result.push_back(ffAdd(word[i], temp[i]));
    }
    return result;
}

vector<vector<byte>> AES::keySchedule(vector<vector<byte>> key, int wordCount, int nk) {
    int i = nk;

    vector<byte> temp;
    byte constant = 0x01;
    while (i < wordCount)
    {
        temp = key[i-1];
        if (i % nk == 0)
        {
            rotWord(temp);
            subWord(temp);
            vector<byte> roundConstant {constant, 0x00, 0x00, 0x00};
            temp = wordXor(temp, roundConstant);
            constant = ffMultiply(constant, 2);
        }
        else if (nk > 6 && i % nk == 4)
        {
            subWord(temp);
        }
        key.push_back(wordXor(key[i-nk], temp));
        i++;
    }
    return key;
}

vector<vector<byte>> AES::transpose(vector<vector<byte>> v) {
    vector<vector<byte>> transposed = v;
    for (auto i = 0; i < 4; i++)
    {
        for (auto j = 0; j < 4; j++)
        {
            transposed[i][j] = v[j][i];
        }

    }
    return transposed;
}
