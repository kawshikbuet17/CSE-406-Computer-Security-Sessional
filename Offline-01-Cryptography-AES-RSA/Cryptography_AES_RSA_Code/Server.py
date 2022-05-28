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
    aes.keyScheduling()
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
        print("Plain Text:")
        print(plainText)
        print()

        aesKey = "BUET CSE17 Batch"
        print("AES Key:")
        print(aesKey)
        print()

        cipherText = aesCipherText(plainText, aesKey)
        print("Sending CipherText:")
        print(cipherText)
        print()
        c.send(cipherText.encode())

        cipherTextList, e, d, n = rsaCipherText(aesKey)
        f = open(str(folderPath)+"/PRK.txt", "w")
        f.write(str(d) + "\n" + str(n))
        f.close()
        print("PRK written in Folder", str(folderPath)+"/PRK.txt")
        print()

        temp = ""
        for i in range(len(cipherTextList)):
            temp += str(cipherTextList[i])
            if i != len(cipherTextList)-1:
                temp+=" "
        # print("to send = ", temp)
        print("Sending Encrypted AES Key:")
        print(temp)
        print()
        c.send(temp.encode())

        print("Sending RSA Public Key:")
        print((str(e)+","+str(n)))
        print()
        c.send((str(e)+","+str(n)).encode())

        print("Matching DPT and Original Plain Text")
        ack = c.recv(1024).decode()
        if ack == "File Write Done":
            with open("Don't Open this/DPT.txt") as f:
                plainText = plainText.split("\n")
                lines = f.readlines()
                print("Plain Text ->", plainText)
                print("DPT ->", lines)
                flag = True
                if len(plainText) != len(lines):
                    flag = False
                else:
                    for i in range(len(plainText)):
                        lines[i] = lines[i].rstrip()
                        if plainText[i] != lines[i]:
                            flag = False
                            break
                if flag == True:
                    print("Matched")
                else:
                    print("Some Error Occured")
                f.close()
        c.close()
        break
