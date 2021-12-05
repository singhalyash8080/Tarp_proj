import random
import string


def key_exchange_send_A(B_public_key, A_private_key, A_public_key ):
    x=""
    for i in A_private_key:
        x+=chr(int(pow(B_public_key, ord(i), A_public_key)))
    return x

def key_exchange_recv_A(y, A_private_key, A_public_key):
    ka=""
    for i in range(len(y)):
        ka+=chr(int(pow(ord(y[i]),ord(A_private_key[i]),A_public_key)))
    return ka

def key_exchange_send_B(B_public_key, B_private_key, A_public_key ):
    y=""
    for i in B_private_key:
        y+=chr(int(pow(B_public_key, ord(i), A_public_key)))
    return y

def key_exchange_recv_B(x, B_private_key, A_public_key):
    kb=""
    for i in range(len(x)):
        kb+=chr(int(pow(ord(x[i]),ord(B_private_key[i]),A_public_key)))
    return kb

key_space = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        #string.punctuation,
        #string.whitespace,
    ]

def generate_key():
        space = "".join(key_space)
        return "".join(random.choice(space) for i in range(0x10))

# A_public_key=23
# B_public_key=9
# A_private_key = generate_key()
# B_private_key = generate_key()
# x= key_exchange_send_A(B_public_key, A_private_key, A_public_key)
# y = key_exchange_send_B(B_public_key, B_private_key, A_public_key)
# ka = key_exchange_recv_A(y, A_private_key, A_public_key)
# kb = key_exchange_recv_B(x, B_private_key, A_public_key)


# print(ka)
# print(kb)