from Crypto.Cipher import AES
import binascii

def encryptor(message,key,mode,iv):
    encrypt_cipher=AES.new(key,mode,iv)
    ciphertext = encrypt_cipher.encrypt(message)
    return ciphertext


def decryptor(ciphertext,key,mode,iv):
    decrypt_cipher = AES.new(key,mode,iv)
    decrypted_msg = decrypt_cipher.decrypt(ciphertext)
    return decrypted_msg


def main():
    message ='HiImMeghnaKanajiGetSomeGroceriesSendme100DollarsHiImMeghnaKanajiDeleteAllTheDataHiImMeghnaKanaji'
    msg1 = 'Give Eve $ 100  '
    key = 'abcdefghijklmnop'  # key lenght = 16 bytes
    mode = AES.MODE_CBC
    no_blocks=len(message)/16 # counting the number of 16 bytes block in the message
    j=0
    iv = '0000000000000000'
    ciphertext_result = []
    # encrypting each block in each for loop.
    cipher_text=encryptor(msg1,key,mode,iv)
    ciphertext1=binascii.b2a_hex(cipher_text)

    decrypted_msg = decryptor(cipher_text,key,mode,iv)
    

    for i in range(0,no_blocks):
        msg = message[j:j+16]  # divinding the string into 16byte block each 
        print "\nplaintext message is:", msg
        if i == 0:
            ciphertext=encryptor(msg,key,mode,iv)
            print "ciphertext is:"+binascii.b2a_hex(ciphertext)
            ciphertext_result.append(ciphertext)
            ciphertext_result[0] = cipher_text           
            
            decrypted_msg = decryptor(ciphertext_result[i],key,mode,iv)
            print "decrypted msg is:", decrypted_msg
        elif i == 1:
            ciphertext=encryptor(msg,key,mode,ciphertext)
            print "ciphertext is:"+binascii.b2a_hex(ciphertext)
            ciphertext_result.append(ciphertext)
                      
            decrypted_msg = decryptor(ciphertext_result[i],key,mode,ciphertext_result[i-1])
            print "decrypted msg is:",decrypted_msg
        else:
            ciphertext=encryptor(msg,key,mode,ciphertext)
            print "ciphertext is:"+binascii.b2a_hex(ciphertext)
            ciphertext_result.append(ciphertext)
                      
            decrypted_msg = decryptor(ciphertext_result[i],key,mode,ciphertext_result[i-1])
            print "decrypted msg is:",decrypted_msg
        
        j += 16
            
if __name__ == '__main__': main()
