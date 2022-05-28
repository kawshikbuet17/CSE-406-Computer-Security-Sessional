import time

from BitVector import BitVector
import math
import random

class RSA:
    def modInverse(self, a, m):
        m0 = m
        y = 0
        x = 1

        if (m == 1):
            return 0

        while (a > 1):
            q = a // m
            t = m
            m = a % m
            a = t
            t = y

            y = x - q * y
            x = t

        if (x < 0):
            x = x + m0
        return x

    def rsaKeyGeneration(self, k):
        bv = BitVector(intVal=0)
        bv = bv.gen_random_bits(k // 2)
        while bv.test_for_primality() == 0:
            bv = bv.gen_random_bits(k//2)
        p = bv.intValue()

        bv = bv.gen_random_bits(k // 2)
        while bv.test_for_primality() == 0:
            bv = bv.gen_random_bits(k // 2)
        q = bv.intValue()

        #     p = 31337
        #     q = 31357

        while p == q:
            bv = bv.gen_random_bits(k // 2)
            while bv.test_for_primality() == 0:
                bv = bv.gen_random_bits(k // 2)
            q = bv.intValue()

        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 2

        while e < phi_n:
            if math.gcd(e, phi_n) == 1:
                break
            e = e + 1

        d = self.modInverse(e, phi_n)

        return int(e), int(d), int(n)


    def XpowYmodM(self, x, y, m):
        res = 1;
        x = x % m
        while y != 0:
            if y & 1 != 0:
                res = (res * (x % m)) % m
            y = y >> 1
            x = (((x % m) * (x % m))) % m
        return res % m

    def encryption(self, P, e, n):
        return self.XpowYmodM(P, e, n)

    def decryption(self, C, d, n):
        return self.XpowYmodM(C, d, n)


if __name__ == '__main__':
    rsa = RSA()
    e, d, n = rsa.rsaKeyGeneration(128)
    print("Public Key = {", e,",",n,"}")
    print("Private Key = {", d, ",", n,"}")

    plainText = "This is a plain text which is to be encrypted. Lets run the code and see what happens"
    print("PlainText =", plainText)
    print()
    cipherText = []
    for ch in plainText:
        ch = ord(ch)
        cipherText.append(rsa.encryption(ch, e, n))
    print("After Encryption = ", cipherText)
    print()
    retrieveText = ""
    for ch in cipherText:
        retrieveText += chr(rsa.decryption(ch, d, n))
    print("After Decryption = ", retrieveText)
    print()
    for k in [16, 32, 64, 128]:
        time1 = time.time_ns()
        e, d, n = rsa.rsaKeyGeneration(k)
        time2 = time.time_ns()
        cipherText = []
        for ch in plainText:
            ch = ord(ch)
            cipherText.append(rsa.encryption(ch, e, n))
        time3 = time.time_ns()
        retrieveText = ""
        for ch in cipherText:
            retrieveText += chr(rsa.decryption(ch, d, n))
        time4 = time.time_ns()
        print("K =", k)
        print("Key Generation time =", time2-time1, "ns")
        print("Encryption time =", time3 - time2, "ns")
        print("Decryption time =", time4 - time3, "ns")
        print()
