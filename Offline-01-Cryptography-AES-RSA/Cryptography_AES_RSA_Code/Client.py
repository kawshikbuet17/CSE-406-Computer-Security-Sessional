import socket
from AES import AES
from RSA import RSA


def getAESkey(cipherTextList):
    with open("Don't Open this/rsa.txt") as f:
        d = f.readline()
        d = int(d)
        print("d =", d)
        n = f.readline()
        n = int(n)
        print("n =", n)
        f.close()
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

cipherTextList = s.recv(1024).decode()
cipherTextList = cipherTextList.split(" ")
cipherTextList = list(map(int, cipherTextList))
# print(cipherTextList)

aesKey = getAESkey(cipherTextList)
print("aesKey retrieve =", aesKey)
aes = AES(aesKey)
aes.setRoundKeys()
decipherText = aes.getDeCipherText(cipherText)
print("DecipherText =", decipherText)

folderPath = """Don't Open this"""
f = open(str(folderPath)+"/decipherText.txt", "w")
f.write(decipherText)
f.close()
s.send("File Write Done".encode())
s.close()

