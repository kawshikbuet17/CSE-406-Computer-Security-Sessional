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
        f = open(str(folderPath)+"/PRK.txt", "w")
        f.write(str(d) + "\n" + str(n))
        f.close()
        temp = ""
        for i in range(len(cipherTextList)):
            temp += str(cipherTextList[i])
            if i != len(cipherTextList)-1:
                temp+=" "
        # print("to send = ", temp)
        c.send(temp.encode())
        ack = c.recv(1024).decode()
        if ack == "File Write Done":
            with open("Don't Open this/DPT.txt") as f:
                plainText = plainText.split("\n")
                lines = f.readlines()
                # print("Plain", plainText)
                # print("lines", lines)
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
                    print("Data sent successfully")
                else:
                    print("Data sent failed")
                f.close()
        c.close()
        break
