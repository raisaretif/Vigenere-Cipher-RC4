def KSA(key):
    keylength = len(key)
    S = range(256)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap

        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def convert_ct(s):
        import binascii
        return [ord(ch) for ch in binascii.unhexlify(s)]

def convert_key(s):
        return [ord(c) for c in s]

def find_pos(value):
        temp = []
        i=0
        while i<len(value):
                j=0
                while j<letters_len:
                        if value[i] == letters[j]:
                                temp.append(j)
                        j = j+1
                i= i+1
        return temp

def encryptRC4(key, plaintext):
    key = convert_key(key)
    keystream = RC4(key)
    ciphertext = ''.join([("%02X" % (ord(c) ^ keystream.next())) for c in plaintext])
    return ciphertext

def decryptRC4(key, ciphertext):
    key = convert_key(key)
    keystream = RC4(key)
    ciphertext = convert_ct(ciphertext)
    plaintext = ''.join([chr(c ^ keystream.next()) for c in ciphertext]) 
    return plaintext
    

def encryptVigenere(keyV, plaintextV, n):
    cipher = []
    pos_key = []
    pos_text = []
    pos_cipher = 0
    keyNEW = []
    plain = []
    keyNEW = map(lambda k:k.lower(),keyV)
    plain = map(lambda p:p.lower(),plaintextV)
    pos_key = find_pos(keyNEW)
    pos_text = find_pos(plain)                                      
    if len(pos_key) > len(pos_text):
        range_list = pos_key
    else :
        range_list = pos_text
    i=0
    j=0
    loop_pass = 0  
    while i<len(range_list) and j<len(range_list) and loop_pass<len(pos_text):
        pos_cipher = n*pos_key[i] + pos_text[j]
        if pos_cipher<letters_len:
            cipher.append(letters[pos_cipher])
        else:
            pos_cipher = pos_cipher-letters_len
            cipher.append(letters[pos_cipher])

        i = i+1
        j = j+1
                        
        if i==len(pos_key) and j<len(pos_text):
            i=0
        elif j==len(pos_text) and i<len(pos_key):
            j=0
        loop_pass = loop_pass + 1
    result = "" .join(cipher)
    return result

if __name__ == '__main__':

    key = 'secret'
    keyV= 'lemon'
    letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9']
    letters_len = len(letters)

    print("1. Encrypt")
    print("2. Decrypt")
    op = raw_input("Choose an option: ")
    
    if(op=="1"): #encrypt rc4-vigenere
        plaintext = raw_input("Write the PlainText: ")
        #encrypt rc4
        enryptRC4String=encryptRC4(key, plaintext)
        enryptRC4StringLOWER=enryptRC4String.lower()
        #encrypt vigenere
        n=1
        enryptRC4StringLOWERHEX = enryptRC4StringLOWER.encode('hex')
        encryptVigenereString=encryptVigenere(keyV, enryptRC4StringLOWERHEX, n)
        print(encryptVigenereString)
    if(op=="2"): #decrypt vigenere-rc4
        ciphertextVigenere = raw_input("Write the CipherText: ")
        #decrypt vigenere
        n=-1
        decryptVigenereString=encryptVigenere(keyV, ciphertextVigenere, n)
        decryptVigenereStringHEX=decryptVigenereString.decode('hex')
        #decrypt rc4
        decryptRC4String = decryptRC4(key, decryptVigenereStringHEX)
        print(decryptRC4String)

