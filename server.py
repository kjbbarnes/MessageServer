import socket
import select
import sys
from thread import *
import random
from Crypto.Cipher import AES

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if len(sys.argv) != 3:
    print "Correct usage: script, IP address, port number"
    exit()
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])
server.bind((IP_address, Port))
server.listen(10)
list_of_clients = []

def encrypt_aes_key(clientPublicKey, aesKey):
    c = 0
    for i in range(0, 128):
        if aesKey[i] == 1:
            c += clientPublicKey[i]
    return c

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def clientthread(conn, addr):
    clientPublicKeyStr = conn.recv(12048)
    clientPublicKey = clientPublicKeyStr.split(',')
    clientPublicKey = list(map(int, clientPublicKey))
    conn.send(str(encrypt_aes_key(clientPublicKey, aesKeyBits)))
    welcomeMessage = aes.encrypt(pad("Welcome to the chatroom!"))
    conn.send(welcomeMessage)
    while True:
        try:
            message = conn.recv(2048)
            plaintext = unpad(aes.decrypt(message))
            if plaintext:
                print "<" + addr[0] + "> " + plaintext
                message_to_send = "<" + addr[0] + "> " + plaintext
                encrypted_message_to_send = aes.encrypt(pad(message_to_send))
                broadcast(encrypted_message_to_send, conn)
            else:
                remove(conn)
        except:
            continue

def broadcast(message, connection):
    for clients in list_of_clients:
        if clients!=connection:
            try:
                clients.send(message) # message is already encrypted, no need to double encrypt
            except:
                clients.close()
                remove(clients)

def remove(connection):
    if connection in list_of_clients:
        list_of_clients.remove(connection)

def aes_key_to_hex(aesKeyBits):
    aesKeyBytes = []
    aesKey = []
    k = 0
    while k < 128:
        byte = []
        for j in range(4):
            byte.append(str(aesKeyBits[k]))
            k += 1
        aesKeyBytes.append(int(''.join(str(e) for e in byte), 2))
    for i in range(32):
        if aesKeyBytes[i] <= 9:
            aesKey.append(str(aesKeyBytes[i]))
        elif aesKeyBytes[i] == 10:
            aesKey.append('A')
        elif aesKeyBytes[i] == 11:
            aesKey.append('B')
        elif aesKeyBytes[i] == 12:
            aesKey.append('C')
        elif aesKeyBytes[i] == 13:
            aesKey.append('D')
        elif aesKeyBytes[i] == 14:
            aesKey.append('E')
        else:
            aesKey.append('F')
    return ''.join(aesKey)


aesKeyBits = []
for i in range(128):
    aesKeyBits.append(random.randint(0, 1))
aesKeyHex = aes_key_to_hex(aesKeyBits)
aes = AES.new(aesKeyHex, AES.MODE_ECB)

while True:
    conn, addr = server.accept()
    list_of_clients.append(conn)
    print addr[0] + " connected"
    start_new_thread(clientthread, (conn, addr))

conn.close()
server.close()
