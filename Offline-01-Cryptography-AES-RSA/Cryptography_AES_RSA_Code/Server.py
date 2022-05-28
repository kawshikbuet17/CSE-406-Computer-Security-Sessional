import socket
import os
from AES import *
from RSA import *

def createFolder(folderPath):
    mypath = folderPath
    if not os.path.isdir(mypath):
        os.makedirs(mypath)

def aesCipherText(plainText, aesKey):
    aes = AES(aesKey)
    aes.setRoundKeys()
    return aes.getCipherText(plainText)

def rsaCipherText(aesKey):
    rsa = RSA()
    e, d, n = rsa.rsaKeyGeneration(128)
    plainText = aesKey
    cipherText = []
    for ch in plainText:
        ch = ord(ch)
        cipherText.append(rsa.encryption(ch, e, n))
    return cipherText, e, d, n

if __name__=="__main__":
    folderPath = """Don't Open this"""
    createFolder(folderPath)
    s = socket.socket()
    print ("Socket successfully created")

    port = 12345

    s.bind(('', port))
    print ("socket binded to %s" %(port))

    s.listen(5)
    print ("socket is listening")

    while True:
        # Establish connection with client.
        c, addr = s.accept()
        print ('Got connection from', addr )

        plainText = "This is a plain text which is to be encrypted. Lets run the code and see what happens"
        aesKey = "BUET CSE 1705043"
        cipherText = aesCipherText(plainText, aesKey)

        c.send(cipherText.encode())

        cipherTextList, e, d, n = rsaCipherText(aesKey)
        f = open(str(folderPath)+"/rsa.txt", "w")
        f.write(str(d) + "\n" + str(n))
        f.close()
        temp = ""
        for i in range(len(cipherTextList)):
            temp += str(cipherTextList[i])
            if i != len(cipherTextList)-1:
                temp+=" "
        # print("to send = ", temp)
        c.send(temp.encode())
        c.close()
        break
