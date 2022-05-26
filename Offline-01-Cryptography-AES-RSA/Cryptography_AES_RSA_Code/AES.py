import copy
from collections import deque

from BitVector import BitVector

import Dataset

class AES:
    def __init__(self, key):
        self.key = key
        keySize = 8 * len(key.encode('utf-8'))
        if keySize == 128:
            self.Nr = 10
        else:
            self.Nr = 10
        self.setKey(key)
    def setPlainText(self, plainText):
        self.plainText = plainText
    def getPlainText(self):
        print(self.plainText)
    def setKey(self, key):
        byteMatrix1D = [ord(i) for i in key]
        word2D = self.matrix1D_to_matrix2D(byteMatrix1D)
        self.roundKeys = self.keyExpansion(word2D, self.Nr)
    def printRoundKeys(self):
        for i in range(0, self.Nr+1):
            print("round ",i, end="->\t")
            for j in range(0, 4):
                for k in range(0, 4):
                    print(hex(self.roundKeys[i][j][k])[2:], end="\t")
            print()
    def keyExpansion(self, word2D, Nr):
        roundKeys = []
        for i in range(0, Nr+1):
            if i == 0:
                roundKeys.append(self.generateRoundKey(i, word2D))
            else:
                roundKeys.append(self.generateRoundKey(i, roundKeys[-1]))
        return roundKeys
    def generateRoundKey(self, roundNo, word2D):
        if roundNo == 0:
            return word2D
        else:
            temp = []
            for i in range(0, 4):
                if i % 4 == 0:
                    temp.append(self.xorList(word2D[i], self.g(word2D[-1], roundNo)))
                else:
                    temp.append(self.xorList(word2D[i], temp[-1]))
            return temp
    def xorList(self, list1, list2):
        temp = []
        for i in range(0, len(list1)):
            temp.append(list1[i] ^ list2[i])
        return temp
    def matrix1D_to_matrix2D(self, matrix1D):
        word2D = []
        for i in range(0, 4):
            temp = []
            for j in range(0, 4):
                temp.append(matrix1D[i*4 + j])
            word2D.append(temp)
        return word2D
    def g(self, word, roundNo):
        temp = self.circularLeftShift(word, -1)
        temp = self.subBytes(temp)
        rc = 1
        rc = self.calculateRoundConst(roundNo, rc)
        const = [rc, 0, 0, 0]
        temp = self.addRoundConst(temp, const)
        return temp
    def calculateRoundConst(self, roundNo, rc):
        temp = rc
        if roundNo == 1:
            return 1
        else:
            for i in range(1, roundNo):
                if roundNo > 1 and temp < 0x80:
                    temp = 2 * temp
                elif roundNo > 1 and temp >= 0x80:
                    temp = (2 * temp) ^ 0x11B
            return temp
    def circularLeftShift(self, word, times):
        temp = deque(word)
        temp.rotate(times)
        return list(temp)
    def addRoundConst(self, word, const):
        temp = word
        for i in range(0, len(word)):
            temp[i] = int(temp[i]) ^ int(const[i])
        return temp
    def subBytes(self, word):
        temp = []
        for i in word:
            b = BitVector(hexstring=hex(i)[2:])
            intVal = b.intValue()
            s = Dataset.Sbox[intVal]
            s = BitVector(intVal=s, size=8)
            temp.append(s)
        return temp


    def encryption(self):
        stateMatrix1D = [ord(i) for i in self.plainText]
        stateMatrix2D = self.matrix1D_to_matrix2D(stateMatrix1D)
        stateMatrixCol2D = self.transposeMatrix(stateMatrix2D)

        for i in range(0, self.Nr+1):
            if i == 0:
                stateMatrixCol2D = self.addRoundKey(stateMatrixCol2D, self.transposeMatrix(self.roundKeys[i]))
            else:

                temp = []
                for j in range(len(stateMatrixCol2D)):
                    temp.append(self.subBytes(stateMatrixCol2D[j]))
                stateMatrixCol2D = temp
                for j in range(len(stateMatrixCol2D)):
                    for k in range(len(stateMatrixCol2D[j])):
                        stateMatrixCol2D[j][k] = int(stateMatrixCol2D[j][k])
                # print("After subBytes")
                # for j in range(0, 4):
                #     for k in range(0, 4):
                #         print(hex(stateMatrixCol2D[j][k])[2:], end="\t")
                #     print()
                # print()
                stateMatrixCol2D = self.shiftRows(stateMatrixCol2D)

                # print("After shiftRows (Mix Column Values)")
                # for j in range(0, 4):
                #     for k in range(0, 4):
                #         print(hex(int(Dataset.Mixer[j][k]))[2:], end="\t")
                #     print()
                # print()
                # print("After shiftRows (State)")
                # for j in range(0, 4):
                #     for k in range(0, 4):
                #         print(hex(stateMatrixCol2D[j][k])[2:], end="\t")
                #     print()
                # print()
                if i != self.Nr:
                    stateMatrixCol2D = self.mixColumns(stateMatrixCol2D)
                    # print("After Mix Columns")
                    # for j in range(0, 4):
                    #     for k in range(0, 4):
                    #         print(hex(stateMatrixCol2D[j][k])[2:], end="\t")
                    #     print()
                    # print()
                stateMatrixCol2D = self.addRoundKey(stateMatrixCol2D, self.transposeMatrix(self.roundKeys[i]))
            print("After Round ", i)
            for j in range(0, 4):
                for k in range(0, 4):
                    print(hex(stateMatrixCol2D[j][k])[2:], end="\t")
                print()
            print()
        self.ciperText = self.transposeMatrix(stateMatrixCol2D)

    def getCipherText(self):
        print("Ciphertext")
        for j in range(0, 4):
            for k in range(0, 4):
                print(hex(self.ciperText[j][k])[2:], end="\t")
        print()
    def shiftRows(self, matrix2D):
        temp = copy.deepcopy(matrix2D)
        for i in range(len(temp)):
            temp[i] = self.circularLeftShift(matrix2D[i], -i)
        return temp

    def mixColumns(self, matrix2D):
        result = [[0 for i in range(len(matrix2D))] for j in range(len(matrix2D))]
        for i in range(len(Dataset.Mixer)):
            for j in range(len(matrix2D[0])):
                for k in range(len(matrix2D[0])):
                    # print(i,j, " = ", i,j, " XOR (", i, k, " DOT ", k, j, ")")
                    AES_modulus = BitVector(bitstring='100011011')
                    bv1 = Dataset.Mixer[i][k]
                    bv2 = BitVector(hexstring=hex(matrix2D[k][j])[2:])
                    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                    result[i][j] = int(result[i][j]) ^ int(bv3)
                # print("result = [",i,j,"]", result[i][j])
        # print(result)
        return result

    def transposeMatrix(self, matrix):
        temp = copy.deepcopy(matrix)
        for i in range(len(temp)):
            for j in range(len(temp)):
                if i > j:
                    temp[i][j], temp[j][i] = temp[j][i], temp[i][j]
        return temp

    def addRoundKey(self, plainText2D, key2D):
        # print("plainText2D", plainText2D)
        # print("key2D", key2D)
        matrix2D = []
        for i in range(4):
            temp = []
            for j in range(4):
                temp.append(plainText2D[i][j] ^ key2D[i][j])
            matrix2D.append(temp)
        return matrix2D
    def decryption(self):
        return 1

if __name__ == "__main__":
    key = "Thats my Kung Fu"
    plainText = "Two One Nine Two"
    aes = AES(key)
    aes.printRoundKeys()
    aes.setPlainText(plainText)

    print("Calling Encryption from MAIN")
    aes.encryption()
    aes.getCipherText()
