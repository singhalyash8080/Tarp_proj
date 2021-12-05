import random
import string
import binascii
from math import ceil
#import the functions to generate an 80/128 bit key schedule and to encrypt plain text and to decrypt te data
from algo import key_schedule_80, key_schedule_128, _encrypt, _decrypt
# from keys import key_exchange_send_A, key_exchange_send_B, key_exchange_recv_A, key_exchange_recv_B


class Twine:

    key_space = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        #string.punctuation,
        #string.whitespace,
    ]


    #makes use of the random function to generate an 80/128 bit key (K) which will be used to generate a 32 bit round key
    def generate_key(self):
        space = "".join(self.key_space)
        return "".join(random.choice(space) for i in range(0x10))


    # generates a 32 bit round key from the perviously generated 80/128 bit keys
    def generate_RK(self, key_inp):
        return key_schedule_128(int(key_inp.encode("utf-8").hex(), 16))

    #blocks corresponds to plain text
    def iterblocks(self, blocks):
        #calc the length of the blocks parameter and calculate how many block of length 16 can be created
        for i in range(ceil(len(blocks) / 16)):
            #since we have used ceil, incase the lenght of blocks isnt an exact multiple of 16 we will have extra bits remaining at the end so return that
            if i * 16 + 16 > len(blocks):
                yield blocks[i * 16 : len(blocks)]
            #return 16 bits from the block till the index falls within the range of block length
            else:
                yield blocks[i * 16 : i * 16 + 16]

    # function to perform encryption 
    # def common_key_enc(self):
    #     A_public_key=23
    #     B_public_key=9
    #     y = key_exchange_send_B(B_public_key, self.dec_key, A_public_key)
    #     ka= key_exchange_recv_A(y, self.enc_key, A_public_key)
    #     return ka
    
    # def common_key_dec(self):
    #     A_public_key=23
    #     B_public_key=9
    #     x= key_exchange_send_A(B_public_key, self.enc_key, A_public_key)
    #     kb = key_exchange_recv_B(x, self.dec_key, A_public_key)
    #     return kb  


    def encrypt(self, plaintext, ka):
        _c = ""
        plaintext = plaintext.encode("utf-8").hex()
        #generate round key

        RK = self.generate_RK(ka)
        #form sub-blocks from the plain text
        for block in self.iterblocks(plaintext):
            #call encrypt function and append the output to _c
            cblock = hex(_encrypt(int(block, 16), RK))[2:]
            _c += cblock
        return _c

    #function to perform decryption
    def decrypt(self, ciphertext, kb):
        #the plain text will be stored in the variable _t
        _t = ""

        #generate round key
        RK = self.generate_RK(kb)
        #taking subblocks from the encrypted text and decrypting them
        for block in self.iterblocks(ciphertext):
            tblock = binascii.unhexlify(hex(_decrypt(int(block, 16), RK))[2:]).decode("windows-1252")
            #call decrypt function and append to output to _t
            _t += tblock
        return _t
