#!/usr/bin/env python


"""
    Copyright (C) 2012 Bo Zhu http://about.bozhu.me
    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""

Sbox = (
    127, 14, 125, 242, 18, 147, 30, 117, 224, 53, 192, 1, 88, 142, 229, 200,
    170, 213, 211, 75, 194, 237, 106, 110, 234, 190, 245, 128, 225, 60, 203, 27,
    140, 86, 65, 143, 13, 126, 201, 52, 193, 139, 87, 181, 135, 20, 207, 158,
    233, 100, 241, 222, 253, 44, 251, 174, 178, 36, 103, 107, 156, 255, 40, 47,
    19, 71, 64, 61, 31, 168, 15, 108, 169, 70, 22, 6, 67, 185, 122, 184,
    150, 153, 138, 96, 183, 177, 221, 124, 94, 95, 118, 35, 134, 57, 29, 141,
    8, 227, 46, 79, 157, 116, 26, 93, 82, 5, 247, 205, 78, 231, 99, 228,
    162, 76, 238, 85, 186, 121, 72, 73, 172, 38, 239, 218, 133, 131, 146, 254,
    112, 209, 77, 21, 137, 252, 0, 180, 74, 175, 152, 9, 159, 49, 161, 68,
    12, 11, 204, 113, 216, 63, 132, 248, 92, 164, 136, 198, 144, 10, 45, 97,
    187, 189, 59, 51, 62, 163, 90, 80, 25, 206, 217, 115, 37, 83, 160, 43,
    145, 220, 219, 199, 58, 105, 155, 7, 123, 195, 120, 104, 243, 69, 3, 17,
    50, 166, 165, 56, 167, 109, 188, 202, 2, 54, 34, 114, 151, 215, 42, 39,
    235, 176, 4, 89, 130, 148, 102, 154, 24, 84, 119, 212, 66, 250, 197, 196,
    101, 246, 232, 55, 249, 191, 16, 226, 91, 129, 240, 210, 214, 28, 149, 111,
    41, 230, 223, 236, 81, 98, 173, 182, 179, 208, 32, 33, 171, 23, 48, 244,
)

InvSbox = (
    134, 11, 200, 190, 210, 105, 75, 183, 96, 139, 157, 145, 144, 36, 1, 70,
    230, 191, 4, 64, 45, 131, 74, 253, 216, 168, 102, 31, 237, 94, 6, 68,
    250, 251, 202, 91, 57, 172, 121, 207, 62, 240, 206, 175, 53, 158, 98, 63,
    254, 141, 192, 163, 39, 9, 201, 227, 195, 93, 180, 162, 29, 67, 164, 149,
    66, 34, 220, 76, 143, 189, 73, 65, 118, 119, 136, 19, 113, 130, 108, 99,
    167, 244, 104, 173, 217, 115, 33, 42, 12, 211, 166, 232, 152, 103, 88, 89,
    83, 159, 245, 110, 49, 224, 214, 58, 187, 181, 22, 59, 71, 197, 23, 239,
    128, 147, 203, 171, 101, 7, 90, 218, 186, 117, 78, 184, 87, 2, 37, 0,
    27, 233, 212, 125, 150, 124, 92, 44, 154, 132, 82, 41, 32, 95, 13, 35,
    156, 176, 126, 5, 213, 238, 80, 204, 138, 81, 215, 182, 60, 100, 47, 140,
    174, 142, 112, 165, 153, 194, 193, 196, 69, 72, 16, 252, 120, 246, 55, 137,
    209, 85, 56, 248, 135, 43, 247, 84, 79, 77, 116, 160, 198, 161, 25, 229,
    10, 40, 20, 185, 223, 222, 155, 179, 15, 38, 199, 30, 146, 107, 169, 46,
    249, 129, 235, 18, 219, 17, 236, 205, 148, 170, 123, 178, 177, 86, 51, 242,
    8, 28, 231, 97, 111, 14, 241, 109, 226, 48, 24, 208, 243, 21, 114, 122,
    234, 50, 3, 188, 255, 26, 225, 106, 151, 228, 221, 54, 133, 52, 127, 61,
)


# learnt from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def text2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def matrix2text(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text


class AES:
    def __init__(self, master_key):
        self.change_key(master_key)

    def change_key(self, master_key):
        self.round_keys = text2matrix(master_key)
        # print self.round_keys

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0]        \
                     ^ Sbox[self.round_keys[i - 1][1]]  \
                     ^ Rcon[i // 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ Sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)

    
    def encrypt(self, plaintext,rounds=10):
        self.plain_state = text2matrix(plaintext)

        self.__add_round_key(self.plain_state, self.round_keys[:4])
        for i in range(1, rounds):
            self.__round_encrypt(self.plain_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.__sub_bytes(self.plain_state)
        self.__shift_rows(self.plain_state)
        self.__add_round_key(self.plain_state, self.round_keys[40:])

        return matrix2text(self.plain_state)
    
    def encrypt_by_stage(self, plaintext):
        
        res_list = []
        self.plain_state = text2matrix(plaintext)

        self.__add_round_key(self.plain_state, self.round_keys[:4])

        for i in range(1, 10):
            self.__round_encrypt(self.plain_state, self.round_keys[4 * i : 4 * (i + 1)])
            res_list.append(matrix2text(self.plain_state))

        self.__sub_bytes(self.plain_state)
        self.__shift_rows(self.plain_state)
        self.__add_round_key(self.plain_state, self.round_keys[40:])
        res_list.append(matrix2text(self.plain_state))
        return res_list

    def decrypt(self, ciphertext):
        self.cipher_state = text2matrix(ciphertext)

        self.__add_round_key(self.cipher_state, self.round_keys[40:])
        self.__inv_shift_rows(self.cipher_state)
        self.__inv_sub_bytes(self.cipher_state)

        for i in range(9, 0, -1):
            self.__round_decrypt(self.cipher_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.__add_round_key(self.cipher_state, self.round_keys[:4])

        return matrix2text(self.cipher_state)

    def __add_round_key(self, s, k):
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]


    def __round_encrypt(self, state_matrix, key_matrix):
        self.__sub_bytes(state_matrix)
        self.__shift_rows(state_matrix)
        self.__mix_columns(state_matrix)
        self.__add_round_key(state_matrix, key_matrix)


    def __round_decrypt(self, state_matrix, key_matrix):
        self.__add_round_key(state_matrix, key_matrix)
        self.__inv_mix_columns(state_matrix)
        self.__inv_shift_rows(state_matrix)
        self.__inv_sub_bytes(state_matrix)

    def __sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = Sbox[s[i][j]]


    def __inv_sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = InvSbox[s[i][j]]


    def __shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


    def __inv_shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

    def __mix_single_column(self, a):
        # please see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)


    def __mix_columns(self, s):
        for i in range(4):
            self.__mix_single_column(s[i])


    def __inv_mix_columns(self, s):
        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = xtime(xtime(s[i][0] ^ s[i][2]))
            v = xtime(xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        self.__mix_columns(s)