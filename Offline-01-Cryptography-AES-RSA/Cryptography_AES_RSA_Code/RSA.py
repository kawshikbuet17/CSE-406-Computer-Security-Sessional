import LargePrimeGenerator
import math
import random


def modInverse(a, m):
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


def rsaKeyGeneration(k):
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

    d = modInverse(e, phi_n)

    return int(e), int(d), int(n)


def ApowBmodM(x, y, m):
    res = 1;
    x = x % m

    while y != 0:
        if y & 1 != 0:
            res = (res * (x % m)) % m
        y = y >> 1
        x = (((x % m) * (x % m))) % m
    #         print(res)
    #     print("final res ", res)
    return (res % m) % m

def encryption(P, e, n):
    return ApowBmodM(P,e,n)

def decryption(C, d, n):
    return ApowBmodM(C,d,n)


if __name__ == '__main__':
    e, d, n = rsaKeyGeneration(128)
    print("e = ", e)
    print("d = ", d)
    print("n = ", n)

    plainText = input()
    cipherText = []
    for ch in plainText:
        ch = ord(ch)
        cipherText.append(encryption(ch, e, n))
    print("After Encryption = ", cipherText)

    retrieveText = ""
    for ch in cipherText:
        retrieveText += chr(decryption(ch, d, n))
    print("After Decryption = ", retrieveText)