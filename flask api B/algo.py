from collections import defaultdict as ddict
#4 bit S-box 
sbox = {
    0x0: 0xC,
    0x1: 0x0,
    0x2: 0xF,
    0x3: 0xA,
    0x4: 0x2,
    0x5: 0xB,
    0x6: 0x9,
    0x7: 0x5,
    0x8: 0x8,
    0x9: 0x3,
    0xA: 0xD,
    0xB: 0x7,
    0xC: 0x1,
    0xD: 0xE,
    0xE: 0x6,
    0xF: 0x4,
}

#permutation box (4-bit) for diffusion during encryption (shuffle)
permutation_enc = {
    0x0: 0x5,
    0x1: 0x0,
    0x2: 0x1,
    0x3: 0x4,
    0x4: 0x7,
    0x5: 0xC,
    0x6: 0x3,
    0x7: 0x8,
    0x8: 0xD,
    0x9: 0x6,
    0xA: 0x9,
    0xB: 0x2,
    0xC: 0xF,
    0xD: 0xA,
    0xE: 0xB,
    0xF: 0xE,
}
#permutation box (4-bit) for diffusion during decryption (shuffle)
permutation_dec = {
    0x0: 0x1,
    0x1: 0x2,
    0x2: 0xB,
    0x3: 0x6,
    0x4: 0x3,
    0x5: 0x0,
    0x6: 0x9,
    0x7: 0x4,
    0x8: 0x7,
    0x9: 0xA,
    0xA: 0xD,
    0xB: 0xE,
    0xC: 0x5,
    0xD: 0x8,
    0xE: 0xF,
    0xF: 0xC,
}

#constants matrix (4 bit)
con = {
    0x01: 0x01,
    0x02: 0x02,
    0x03: 0x04,
    0x04: 0x08,
    0x05: 0x10,
    0x06: 0x20,
    0x07: 0x03,
    0x08: 0x06,
    0x09: 0x0C,
    0x0A: 0x18,
    0x0B: 0x30,
    0x0C: 0x23,
    0x0D: 0x05,
    0x0E: 0x0A,
    0x0F: 0x14,
    0x10: 0x28,
    0x11: 0x13,
    0x12: 0x26,
    0x13: 0x0F,
    0x14: 0x1E,
    0x15: 0x3C,
    0x16: 0x3B,
    0x17: 0x35,
    0x18: 0x29,
    0x19: 0x11,
    0x1A: 0x22,
    0x1B: 0x07,
    0x1C: 0x0E,
    0x1D: 0x1C,
    0x1E: 0x38,
    0x1F: 0x33,
    0x20: 0x25,
    0x21: 0x09,
    0x22: 0x12,
    0x23: 0x24,
}


#returns the Mapping of a particular element according to the S box
def sbox_value(i):
    return sbox[i]

#returns a 3 bit binary literal which is used in generating the round key from a randomly generated key
def con_L(r):
    return con[r] & 0b111

#returns a 3 bit binary literal which is used in generating the round key from a randomly generated key
def con_H(r):
    return con[r] >> 3 & 0b111


def rot_4(bits):
    #places the first bit at the end to perform rotation
    return bits[1:] + bits[:1]


def rot_16(bits):
    #places the first 4 bits at the end of the list to perform rotation of a 4 bit sub-block
    return bits[4:] + bits[:4]

#Function used in generation of round key from and 80 or 128 bit key and in encryption and decrption
def get_4_bits(source, pos):
    return source >> pos * 4 & 0xF

#Function used in generation of round key from and 80 or 128 bit key
def append_4_bits(source, bits):
    return source << 4 | bits

#function to generate round key
def key_schedule_80(key):
    RK_32, WK_80 = ddict(ddict), []
    for i in range(20):
        #divides the key into 20 sub-blocks containing 4 bits each
        WK_80.append(get_4_bits(key, 20 - 1 - i))
        #generation of 36 round keys (one for each round)
        #reach round key contains 8 4 bit sub-blocks as defined
    for r in range(1, 36):
        (
            RK_32[r][0],
            RK_32[r][1],
            RK_32[r][2],
            RK_32[r][3],
            RK_32[r][4],
            RK_32[r][5],
            RK_32[r][6],
            RK_32[r][7],
        ) = (
            WK_80[1],
            WK_80[3],
            WK_80[4],
            WK_80[6],
            WK_80[13],
            WK_80[14],
            WK_80[15],
            WK_80[16],
        )
        #after a round key is calculated for a particular round, the 80 bit or 128 bit key is changed to obtain a diff round key
        #sbox_value(Wk_80[index]) returns the S box mapping for that element which is then computed with another value from the key dictionary under XOR operation
        WK_80[1] = WK_80[1] ^ sbox_value(WK_80[0])
        WK_80[4] = WK_80[4] ^ sbox_value(WK_80[16])
        #con_H and #con_L return 3 bit binary literals after right shift of the element from the CON martix and performing bit-wise and
        WK_80[7] = WK_80[7] ^ con_H(r)
        WK_80[19] = WK_80[19] ^ con_L(r)
        #here 4 sub block are taken (Index 0-3) which totals up to 16 bits
        #places the first sub-block at the end to perform rotation
        WK0_WK3_16 = rot_4(WK_80[:4])
        #assigning WK0_WK3_16 back to WK_80
        for j in range(len(WK0_WK3_16)):
            WK_80[j] = WK0_WK3_16[j]
        #here all the 20 sub blocks are taken (Index 0-19) which totals up to 80 bits
        #the first 4 sub blocks are placed at the end of the list to perform rotation
        WK0_WK19_80 = rot_16(WK_80[:20])
        #assigning WK0_WK19_80 back to WK_80
        for k in range(len(WK0_WK19_80)):
            WK_80[k] = WK0_WK19_80[k]
    (
        RK_32[36][0],
        RK_32[36][1],
        RK_32[36][2],
        RK_32[36][3],
        RK_32[36][4],
        RK_32[36][5],
        RK_32[36][6],
        RK_32[36][7],
    ) = (
        WK_80[1],
        WK_80[3],
        WK_80[4],
        WK_80[6],
        WK_80[13],
        WK_80[14],
        WK_80[15],
        WK_80[16],
    )
    return RK_32


def key_schedule_128(key):
    RK_32, WK_128 = ddict(ddict), []
    for i in range(32):
        WK_128.append(get_4_bits(key, 32 - 1 - i))
    for r in range(1, 36):
        (
            RK_32[r][0],
            RK_32[r][1],
            RK_32[r][2],
            RK_32[r][3],
            RK_32[r][4],
            RK_32[r][5],
            RK_32[r][6],
            RK_32[r][7],
        ) = (
            WK_128[2],
            WK_128[3],
            WK_128[12],
            WK_128[15],
            WK_128[17],
            WK_128[18],
            WK_128[28],
            WK_128[31],
        )
        WK_128[1] = WK_128[1] ^ sbox_value(WK_128[0])
        WK_128[4] = WK_128[4] ^ sbox_value(WK_128[16])
        WK_128[23] = WK_128[23] ^ sbox_value(WK_128[30])
        WK_128[7] = WK_128[7] ^ con_H(r)
        WK_128[19] = WK_128[19] ^ con_L(r)
        WK0_WK3_16 = rot_4(WK_128[:4])
        for j in range(len(WK0_WK3_16)):
            WK_128[j] = WK0_WK3_16[j]
        WK0_WK31_128 = rot_16(WK_128[:32])
        for k in range(len(WK0_WK31_128)):
            WK_128[k] = WK0_WK31_128[k]
    (
        RK_32[36][0],
        RK_32[36][1],
        RK_32[36][2],
        RK_32[36][3],
        RK_32[36][4],
        RK_32[36][5],
        RK_32[36][6],
        RK_32[36][7],
    ) = (
        WK_128[2],
        WK_128[3],
        WK_128[12],
        WK_128[15],
        WK_128[17],
        WK_128[18],
        WK_128[28],
        WK_128[31],
    )
    #returning the RK matrix (36 rows 32 bit columns)
    return RK_32


def _encrypt(P, RK):
    #P corresponds to plain text 
    #64 bit block cipher which generates 16 sub-blocks of 4 bits each 
    #X_16 is a collection of these 16 4 bit sub blocks
    #The cipher text generated will be stored in C
    RK_32, X_16, C = dict(RK), ddict(lambda: ddict(int)), 0x0
    #forming an initial entry into X_16 by appending 16 4 bit sub blocks from the plain text
    for i in range(16):
        X_16[1][i] = get_4_bits(P, 16 - 1 - i)
    # TWINE is derived from the fiestel architechture so at each point the expression at hand will be divided into 2 parts Left and right consisting of 32 bits each
    for i in range(1, 36):
        #right part of the 64 bit block
        for j in range(0, 8):
            #Updating the right hand side of the expression by performing XOR operations between the S box mapping, round key and present expression 
            X_16[i][2 * j + 1] = sbox_value(X_16[i][2 * j] ^ RK_32[i][j]) ^ X_16[i][2 * j + 1]
        #Left hand side of the 64 bit block
        for h in range(0, 16):
            #Updating the right hand side of the expression by using the permutation box
            X_16[i + 1][permutation_enc[h]] = X_16[i][h]
    #computation for the 36th round
    #perfromed separately as we omit permutation in the 36th round
    for j in range(0, 8):
        X_16[36][2 * j + 1] = sbox_value(X_16[36][2 * j] ^ RK_32[36][j]) ^ X_16[36][2 * j + 1]
    #adding bits from X_16 to the cipher text after performing right shift and bit wise and operation
    for i in range(16):
        C = append_4_bits(C, X_16[36][i])
    #returning the 64 bit cipher text generated
    return C

def _decrypt(C, RK):
    #C stands for cipher text
    #Plain text will be stored in P
    #64 bit block cipher which generates 16 sub-blocks of 4 bits each 
    #X_16 is a collection of these 16 4 bit sub blocks
    RK_32, X_16, P = dict(RK), ddict(lambda: ddict(int)), 0x0
    #forming an initial entry into X_16 by appending 16 4 bit sub blocks from the cipher text
    for i in range(16):
        X_16[36][i] = get_4_bits(C, 16 - 1 - i)
    # TWINE is derived from the fiestel architechture so at each point the expression at hand will be divided into 2 parts Left and right consisting of 32 bits each
    for i in range(36, 1, -1):
        #right part of the 64 bit block
        for j in range(0, 8):
            #Updating the right hand side of the expression by performing XOR operations between the S box mapping, round key and present expression 
            X_16[i][2 * j + 1] = sbox_value(X_16[i][2 * j] ^ RK_32[i][j]) ^ X_16[i][2 * j + 1]
        #Left hand side of the 64 bit block
        for h in range(0, 16):
            #Updating the right hand side of the expression by using the decryption permutation box 
            X_16[i - 1][permutation_dec[h]] = X_16[i][h]
    #computation for the 36th round
    #perfromed separately as we omit permutation in the 36th round
    for j in range(0, 8):
        X_16[1][2 * j + 1] = sbox_value(X_16[1][2 * j] ^ RK_32[1][j]) ^ X_16[1][2 * j + 1]
    #adding bits from X_16 to the plain text after performing right shift and bit wise and operation
    for i in range(16):
        P = append_4_bits(P, X_16[1][i])
    #returning the plain text
    return P
