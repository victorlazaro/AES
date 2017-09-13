//
// Created by Victor Lazaro on 9/8/17.
//

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


void AES::mixColumns(const vector<vector<byte>>& fixedMatrix) {


    vector<vector<byte>> newState = state;
    vector<vector<byte>> transposed = transpose(state);

    for (auto i = 0; i < 4; i++) // fixed rows
    {
        for (auto j = 0; j < 4; j++) // state columns
        {
            byte val = 0x00;
            for (auto k = 0; k < 4; k++) // state rows
            {
                byte mult = ffMultiply(transposed[k][j], fixedMatrix[i][k]);
                val = ffAdd(mult, val);
            }
            newState[i][j] = val;
        }
    }
    state = transpose(newState);
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

    state = std::move(input);
    printMatrix(transpose(state));
    int wordCount = Nb * (nr + 1);
    expandedKey = keySchedule(std::move(inputKey), wordCount, nk);
    addRoundKey(0);
    printMatrix(transpose(state));
    for (int i = 1; i < nr; i++)
    {
        subBytes();
        printMatrix(transpose(state));
        shiftRows();
        printMatrix(transpose(state));
        mixColumns(fixed);
        printMatrix(transpose(state));
        addRoundKey(i * 4);
        printMatrix(transpose(state));
    }

    subBytes();
    shiftRows();
    printMatrix(transpose(state));
    addRoundKey(wordCount - 4);
    printMatrix(transpose(state));
}

void AES::invCypher(vector<vector<byte>> input, vector<vector<byte>> inputKey, int nk, int nr) {

    state = std::move(input);
    printMatrix(transpose(state));
    int wordCount = Nb * (nr + 1);
    expandedKey = keySchedule(std::move(inputKey), wordCount, nk);
    addRoundKey(nr * Nb);
    printMatrix(transpose(state));
    for (int i = nr - 1; i >= 1 ; i--)
    {
        invShiftRows();
        printMatrix(transpose(state));
        invSubBytes();
        printMatrix(transpose(state));
        addRoundKey(i * Nb);
        printMatrix(transpose(state));
        invMixColumns();
        printMatrix(transpose(state));
    }

    invShiftRows();
    printMatrix(transpose(state));
    invSubBytes();
    printMatrix(transpose(state));
    addRoundKey(0);
    printMatrix(transpose(state));
}


void AES::invSubBytes() {

    for (auto i = 0; i < 4; i++)
    {
        for (auto j = 0; j < 4; j++)
        {
            state[i][j] = inv_s[(state[i][j] >> 4) & 0x0F][state[i][j] & 0x0F];
        }
    }

}

void AES::invShiftRows() {

    vector<vector<byte>> transposed = transpose(state);

    for (auto i = 1; i < 4; i++)
    {
        for (int j = 0; j < i; j++)
        {
            invRotWord(transposed[i]);
        }
    }

    state = transpose(transposed);
}

void AES::invMixColumns() {
    mixColumns(invFixed);
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

void AES::invRotWord(vector<byte> &row) {

    byte temp = row[3];
    row[3] = row[2];
    row[2] = row[1];
    row[1] = row[0];
    row[0] = temp;

}

const vector<vector<byte>> &AES::getState() const {
    return state;
}
