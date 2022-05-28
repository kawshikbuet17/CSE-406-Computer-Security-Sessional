import time

import LargePrimeGenerator
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
            # q is quotient
            q = a // m

            t = m

            # m is remainder now, process
            # same as Euclid's algo
            m = a % m
            a = t
            t = y

            # Update x and y
            y = x - q * y
            x = t

        # Make x positive
        if (x < 0):
            x = x + m0

        return x


    def rsaKeyGeneration(self, k):
        p = LargePrimeGenerator.generatePrime(k / 2)
        q = LargePrimeGenerator.generatePrime(k / 2)
        #     p = 31337
        #     q = 31357

        while p == q:
            q = LargePrimeGenerator.generatePrime(k / 2)

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
        return (res % m) % m

    def encryption(self, P, e, n):
        return self.XpowYmodM(P, e, n)

    def decryption(self, C, d, n):
        return self.XpowYmodM(C, d, n)


if __name__ == '__main__':
    rsa = RSA()
    e, d, n = rsa.rsaKeyGeneration(128)
    print("e = ", e)
    print("d = ", d)
    print("n = ", n)

    plainText = "This is a plain text which is to be encrypted. Lets run the code and see what happens"
    print("PlainText =", plainText)

    cipherText = []
    for ch in plainText:
        ch = ord(ch)
        cipherText.append(rsa.encryption(ch, e, n))
    print("After Encryption = ", cipherText)

    retrieveText = ""
    for ch in cipherText:
        retrieveText += chr(rsa.decryption(ch, d, n))
    print("After Decryption = ", retrieveText)

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

        print("K =", k, "Key Generation time\t", time2-time1, "ns")
        print("K =", k, "Encryption time\t", time3 - time2, "ns")
        print("K =", k, "Decryption time\t", time4 - time3, "ns")
        print("K =", k, "Total time\t", time4-time1, "ns")