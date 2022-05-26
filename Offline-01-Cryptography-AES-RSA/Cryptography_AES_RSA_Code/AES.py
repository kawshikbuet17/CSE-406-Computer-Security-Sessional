from collections import deque

from BitVector import BitVector

import Dataset

class AES:
    Nr = 10
    def __init__(self, key):
        self.key = key
        self.byteMatrix1D = [ord(i) for i in key]
        self.word2D = self.byteMatrix1D_to_word2D(self.byteMatrix1D)
        # print(self.word2D)
        self.roundKeys = self.keyExpansion(self.word2D, self.Nr)
        self.printRoundKeys()

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
                    # print("multiply ", i, " g")
                    temp.append(self.xorList(word2D[i], self.g(word2D[-1], roundNo)))
                else:
                    # print("multiply ", i, " ", i-1)
                    temp.append(self.xorList(word2D[i], temp[-1]))
            return temp

    def xorList(self, list1, list2):
        temp = []
        for i in range(0, len(list1)):
            temp.append(list1[i] ^ list2[i])
        return temp

    def byteMatrix1D_to_word2D(self, byteMatrix1D):
        word2D = []
        for i in range(0, 4):
            temp = []
            for j in range(0, 4):
                temp.append(byteMatrix1D[i*4+j])
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
    def shiftRows(self):
        return 1
    def mixColumns(self):
        return 1
    def addKey(self):
        return 1
    def encryption(self):
        return 1

    def decryption(self):
        return 1
    def printF(self, item):
        print(item)

if __name__ == '__main__':
    aes = AES('Thats my Kung Fu')


