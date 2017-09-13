//
// Created by Victor Lazaro on 9/8/17.
//

#include <sstream>
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

    int round = 0;
    state = std::move(input);
    printVal(round, "input", state);
    int wordCount = Nb * (nr + 1);
    expandedKey = keySchedule(std::move(inputKey), wordCount, nk);
    printVal(round, "k_sch", getCurrKey(0));
    addRoundKey(0);
    for (round = 1; round < nr; round++)
    {
        printVal(round, "start", state);
        subBytes();
        printVal(round, "s_box", state);
        shiftRows();
        printVal(round, "s_row", state);
        mixColumns(fixed);
        printVal(round, "m_col", state);
        printVal(round, "k_sch", getCurrKey(round * 4));
        addRoundKey(round * 4);
    }

    subBytes();
    printVal(round, "s_box", state);
    shiftRows();
    printVal(round, "s_row", state);
    printVal(round, "k_sch", getCurrKey(round * 4));
    addRoundKey(wordCount - 4);
    printVal(round, "output", state);
}

void AES::invCypher(vector<vector<byte>> input, vector<vector<byte>> inputKey, int nk, int nr) {

    int round = nr;
    state = std::move(input);
    printVal(nr - round, "iinput", state);
    int wordCount = Nb * (nr + 1);
    printVal(nr - round, "ik_sch", getCurrKey(round * 4));
    expandedKey = keySchedule(std::move(inputKey), wordCount, nk);
    addRoundKey(nr * Nb);
    for (round = nr - 1; round >= 1 ; round--)
    {
        printVal(nr - round, "istart", state);
        invShiftRows();
        printVal(nr - round, "is_row", state);
        invSubBytes();
        printVal(nr - round, "is_box", state);
        addRoundKey(round * Nb);
        printVal(nr - round, "ik_sch", getCurrKey(round * Nb));
        invMixColumns();
    }

    invShiftRows();
    printVal(nr - round, "is_row", state);
    invSubBytes();
    printVal(nr - round, "is_box", state);
    addRoundKey(0);
    printVal(0, "ioutput", state);
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

void AES::printVal(int round, string step, vector<vector<byte>> state) {

    cout << "round[ " + to_string(round) + "]." + step + "\t";

    string stateStr;
    for (int i = 0; i < state.size(); i++)
    {
        for (int j = 0; j < state[i].size(); j++)
        {
            printf("%.2x", state[i][j]);
        }
    }
    cout << "\n";
}

vector<vector<byte>> AES::getCurrKey(int startIndex) {

    vector<vector<byte>> key = {{0,0,0,0},
                                {0,0,0,0},
                                {0,0,0,0},
                                {0,0,0,0}};

    for (auto i = 0; i < 4; i++)
    {
        for (auto j = 0; j < 4; j++)
        {
            key[i][j] = expandedKey[i + startIndex][j];
        }
    }
    return key;
}
