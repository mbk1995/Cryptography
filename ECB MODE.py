from Crypto.Cipher import AES
import binascii

def encryptor(message,key,mode):
    encrypt_cipher=AES.new(key,mode)
    ciphertext = encrypt_cipher.encrypt(message)
    return ciphertext


def decryptor(ciphertext,key,mode):
    decrypt_cipher = AES.new(key,mode)
    decrypted_msg = decrypt_cipher.decrypt(ciphertext)
    return decrypted_msg


def main():
    message ='HiImMeghnaKanajiGetSomeGroceriesSendme100DollarsHiImMeghnaKanajiDeleteAllTheDataHiImMeghnaKanaji'
    msg1 = 'Give Eve $ 100  '
    key = 'abcdefghijklmnop'  # key lenght = 16 bytes
    mode = AES.MODE_ECB
    no_blocks=len(message)/16 # counting the number of 16 bytes block in the message
    j=0
    cipher_text=encryptor(msg1,key,mode)
    ciphertext1=binascii.b2a_hex(cipher_text)

    decrypted_msg = decryptor(cipher_text,key,mode)
    
    cipher_result = []
    # encrypting each block in each for loop.
    for i in range(0,no_blocks):
        msg = message[j:j+16]  # divinding the string into 16byte block each 
        print "\nplaintext message is:", msg
        if i == 1:
            ciphertext=encryptor(msg,key,mode)
            cipher_result.append(ciphertext)
            ciphertext = cipher_text
            print "ciphertext is:"+binascii.b2a_hex(ciphertext)
            decrypted_msg = decryptor(ciphertext,key,mode)
            print "decrypted message is:", decrypted_msg
        elif i==3:
            ciphertext=encryptor(msg,key,mode)
            cipher_result.append(ciphertext)
            ciphertext = cipher_text
            print "ciphertext is:"+binascii.b2a_hex(ciphertext)
            decrypted_msg = decryptor(ciphertext,key,mode)
            print "decrypted message is:", decrypted_msg

        else:
            ciphertext=encryptor(msg,key,mode)
            cipher_result.append(ciphertext)
            print "ciphertext is:"+binascii.b2a_hex(ciphertext)
            decrypted_msg = decryptor(ciphertext,key,mode)
            print "decrypted message is:", decrypted_msg

        j += 16
  
if __name__ == '__main__': main()
