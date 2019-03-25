import socket
import select
import sys
import random
from Crypto.Cipher import AES

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if len(sys.argv) != 3:
    print "Correct usage: script, IP address, port number"
    exit()
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])

def inverse(u, v):
    u0 = u
    v0 = v
    t0 = 0
    t = 1
    s0 = 1
    s = 0
    q = v0 / u0
    r = v0 - q* u0
    while r > 0:
        temp = t0 - q * t
        t0 = t
        t = temp
        temp = s0 - q * s
        s0 = s
        s = temp
        v0 = u0
        u0 = r
        q = v0 / u0
        r = v0 - q * u0
    r = u0
    if r == 1:
        if t > 0:
            return t
        else:
            return t + v
    else:
        return 0

def decrypt_aes_key(privateKey, c):
    perm = privateKey[0]
    M = privateKey[1]
    W = privateKey[2]
    seq = privateKey[3]
    answer = [0]*128
    plaintext = [0]*128
    s = inverse(W, M)
    d = (long(s) * long(c)) % long(M)
    for i in reversed(range(128)):
        if d >= seq[i]:
            d -= seq[i]
            answer[i] = 1
        else:
            answer[i] = 0
    for j in range(128):
        plaintext[j] = answer[perm[j]]
    return plaintext

def gcd(u, v):
    while u != v:
        if u > v:
            u = u - v
        else:
            v = v - u
    return u

def generate_private_key():
    seq = []
    for i in range(0, 128):
        seq.append(sum(seq) + random.randint(1, 5))
    M = sum(seq) + random.randint(1, 7)
    W = random.randint(2, M-1)
    while(gcd(M, W) != 1):
        W = W - 1
    perm = range(128)
    random.shuffle(perm)
    return (perm, M, W, seq)

def generate_public_key(privateKey):
    publicKey = []
    perm = privateKey[0]
    M = privateKey[1]
    W = privateKey[2]
    seq = privateKey[3]
    for i in range(0, 128):
        publicKey.append((W * seq[perm[i]]) % M)
    return publicKey

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

privateKey = generate_private_key()
publicKey = generate_public_key(privateKey)
server.connect((IP_address, Port))
publicKeyStr = ','.join(str(e) for e in publicKey)
server.send(publicKeyStr)
encryptedAesKey = server.recv(41)
aesKeyBits = decrypt_aes_key(privateKey, encryptedAesKey)
aesKeyHex = aes_key_to_hex(aesKeyBits)
aes = AES.new(aesKeyHex, AES.MODE_ECB)

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

while True:
    sockets_list = [sys.stdin, server]
    read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])

    for socks in read_sockets:
        if socks == server:
            encrypted_message = socks.recv(2048)
            message = unpad(aes.decrypt(encrypted_message))
            print message
        else:
            message = sys.stdin.readline()
            encrypted_message = aes.encrypt(pad(message))
            server.send(encrypted_message)
            sys.stdout.write("<You> ")
            sys.stdout.write(message)
            sys.stdout.flush()

server.close()
