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
        temp = self.circularShift(word, -1)
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
    def circularShift(self, word, times):
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


    def encryption(self, plainText):
        stateMatrix1D = [ord(i) for i in plainText]
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

                stateMatrixCol2D = self.shiftRows(stateMatrixCol2D)

                if i != self.Nr:
                    stateMatrixCol2D = self.mixColumns(stateMatrixCol2D)
                stateMatrixCol2D = self.addRoundKey(stateMatrixCol2D, self.transposeMatrix(self.roundKeys[i]))
            # print("After Encryption Round ", i)
            # self.printInHex(stateMatrixCol2D)
        ciperText = self.transposeMatrix(stateMatrixCol2D)
        return self.retrieveText(ciperText)

    def printCipherText(self, cipherText):
        print("Ciphertext")
        for j in range(0, 4):
            for k in range(0, 4):
                print(hex(cipherText[j][k])[2:], end="\t")
        print()
    def shiftRows(self, matrix2D):
        temp = copy.deepcopy(matrix2D)
        for i in range(len(temp)):
            temp[i] = self.circularShift(matrix2D[i], -i)
        return temp

    def mixColumns(self, matrix2D):
        result = [[0 for i in range(len(matrix2D))] for j in range(len(matrix2D))]
        for i in range(len(Dataset.Mixer)):
            for j in range(len(matrix2D[0])):
                for k in range(len(matrix2D[0])):
                    AES_modulus = BitVector(bitstring='100011011')
                    bv1 = Dataset.Mixer[i][k]
                    bv2 = BitVector(hexstring=hex(matrix2D[k][j])[2:])
                    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                    result[i][j] = int(result[i][j]) ^ int(bv3)
        return result

    def transposeMatrix(self, matrix):
        temp = copy.deepcopy(matrix)
        for i in range(len(temp)):
            for j in range(len(temp)):
                if i > j:
                    temp[i][j], temp[j][i] = temp[j][i], temp[i][j]
        return temp

    def addRoundKey(self, plainText2D, key2D):
        matrix2D = []
        for i in range(4):
            temp = []
            for j in range(4):
                temp.append(int(plainText2D[i][j]) ^ int(key2D[i][j]))
            matrix2D.append(temp)
        return matrix2D
    def decryption(self, cipherText):
        stateMatrix1D = [ord(i) for i in cipherText]
        stateMatrix2D = self.matrix1D_to_matrix2D(stateMatrix1D)
        stateMatrixCol2D = self.transposeMatrix(stateMatrix2D)

        for i in range(0, self.Nr+1):
            if i == 0:
                stateMatrixCol2D = self.addRoundKey(stateMatrixCol2D, self.transposeMatrix(self.roundKeys[self.Nr - i]))
            else:
                for j in range(len(stateMatrixCol2D)):
                    for k in range(len(stateMatrixCol2D[j])):
                        stateMatrixCol2D[j][k] = int(stateMatrixCol2D[j][k])
                stateMatrixCol2D = self.inverseShiftRows(stateMatrixCol2D)

                temp = []
                for j in range(len(stateMatrixCol2D)):
                    temp.append(self.inverseSubBytes(stateMatrixCol2D[j]))
                stateMatrixCol2D = temp
                stateMatrixCol2D = self.addRoundKey(stateMatrixCol2D, self.transposeMatrix(self.roundKeys[self.Nr-i]))

                if i != self.Nr:
                    stateMatrixCol2D = self.inverseMixColumns(stateMatrixCol2D)

            # print("After Decryption Round ", i)
            # self.printInHex(stateMatrixCol2D)
        stateMatrixCol2D = self.transposeMatrix(stateMatrixCol2D)
        return self.retrieveText(stateMatrixCol2D)

    def printInHex(self, matrix2D):
        for j in range(0, 4):
            for k in range(0, 4):
                print(hex(matrix2D[j][k])[2:], end="\t")
            print()
        print()

    def retrieveText(self, matrix2D):
        retriveText = ""
        for i in range(0, 4):
            for j in range(0, 4):
                retriveText += chr(matrix2D[i][j])
        return retriveText

    def inverseShiftRows(self, matrix2D):
        temp = copy.deepcopy(matrix2D)
        for i in range(len(temp)):
            temp[i] = self.circularShift(matrix2D[i], i)
        return temp
    def inverseSubBytes(self, word):
        temp = []
        for i in word:
            b = BitVector(hexstring=hex(i)[2:])
            intVal = b.intValue()
            s = Dataset.InvSbox[intVal]
            s = BitVector(intVal=s, size=8)
            temp.append(s)
        return temp

    def inverseMixColumns(self, matrix2D):
        result = [[0 for i in range(len(matrix2D))] for j in range(len(matrix2D))]
        for i in range(len(Dataset.Mixer)):
            for j in range(len(matrix2D[0])):
                for k in range(len(matrix2D[0])):
                    AES_modulus = BitVector(bitstring='100011011')
                    bv1 = Dataset.InvMixer[i][k]
                    bv2 = BitVector(hexstring=hex(matrix2D[k][j])[2:])
                    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                    result[i][j] = int(result[i][j]) ^ int(bv3)
        return result
    def getCipherText(self, plainText):
        cipherText = ""
        while len(plainText) != 0:
            temp = plainText[:16]
            for i in range(16-len(temp)):
                temp += "$"
            cipherText += self.encryption(temp)
            plainText = plainText[16:]
        return cipherText

    def getDeCipherText(self, cipherText):
        deCipherText = ""
        while len(cipherText) != 0:
            temp = cipherText[:16]
            deCipherText += self.decryption(temp)
            cipherText = cipherText[16:]
        return deCipherText

if __name__ == "__main__":
    key = "BUET CSE 1705043"
    plainText = "This is a plain text which is to be encrypted. Lets run the code and see what happens"
    aes = AES(key)
    aes.printRoundKeys()
    print("PlainText = \t", plainText)
    cipherText = aes.getCipherText(plainText)
    print("CipherText = \t", cipherText)
    print("DeCipherText = \t", aes.getDeCipherText(cipherText))
