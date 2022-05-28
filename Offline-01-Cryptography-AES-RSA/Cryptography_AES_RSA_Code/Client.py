import socket
from AES import AES
from RSA import RSA


def getAESkey(cipherTextList):
    with open("Don't Open this/PRK.txt") as f:
        d = f.readline()
        d = int(d)
        n = f.readline()
        n = int(n)
        f.close()
        print("PRK from file:")
        print("{", d,",", n,"}")
        print()
        rsa = RSA()
        aesKey = ""
        for ch in cipherTextList:
            aesKey += chr(rsa.decryption(ch, d, n))
        return aesKey

s = socket.socket()

port = 12345

s.connect(('127.0.0.1', port))

cipherText = s.recv(1024).decode()
cipherText = str(cipherText)
print("Received AES CipherText:")
print(cipherText)
print()

cipherTextList = s.recv(1024).decode()
cipherTextList = cipherTextList.split(",")
cipherTextList = list(map(int, cipherTextList))
print("Received Encrypted AES Key:")
print(cipherTextList)
print()

publicKeyOfRsa = s.recv(1024).decode()
print("Received PUK:")
print("{", publicKeyOfRsa, "}")
print()

aesKey = getAESkey(cipherTextList)
print("aesKey retrieve:")
print(aesKey)
print()

aes = AES(aesKey)
aes.keyScheduling()
decipherText = aes.getDeCipherText(cipherText)
print("DecipherText:")
print(decipherText)
print()

folderPath = """Don't Open this"""
f = open(str(folderPath)+"/DPT.txt", "w")
f.write(decipherText)
f.close()
s.send("File Write Done".encode())
s.close()

