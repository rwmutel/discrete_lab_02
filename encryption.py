'''
Module for RSA encryption by Roman Mutel
'''

from sympy import randprime

# hardcoded alphabet for coding
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' + \
        'АБВГҐДЕЄЖЗИІЇКЛМНОПРСТУФХЦЧШЩЬЮЯабвгґдеєжзиіїйклмнопрстуфхцчшщьюя01234567890!@#$%^&*()_+-=? '

def get_letter(order: int) -> str:
    # alphabet length is 144
    return ALPHABET[order]

def get_order(letter: str) -> int:
    return ALPHABET.find(letter)

def gcd(a, b):
    if a % b == 0:
        return b
    return gcd(b, a % b)

def generate_key(bit_len, p=0, q=0):
    # if p and q aren't set by the user, generate them
    if (p,q) == (0,0):
        p = randprime(2 ** (bit_len - 1), 2 ** bit_len - 1)
        q = randprime(2 ** (bit_len - 1), 2 ** bit_len - 1)

    e = 10 # hard coded value
    l = (p - 1) * (q - 1)
    while gcd(l, e) != 1 or e % 2 == 0:
        e += 1
    return p, q, e

def generate_secret_key(e, p, q):
    return modular_inverse(e, (p - 1)*(q - 1))

def modular_inverse(a, m):
    '''
    Finds modular multiplicative inverse of a under modulo m
    '''
    x,y = 1,0
    m0 = m

    if gcd(m, a) != 1:
        return

    while a > 1:
        q = a // m
        t = m
        
        m = a % m
        a = t
        t = y

        y = x - q * y
        x = t

    if x < 0:
        x += m0

    return x

def get_block_length(n):
    block_len = 1
    number = 144 # alphabet length
    while number < n:
        number += 144 * 1000 ** block_len
        block_len += 1
    return 3 * (block_len - 1)

def split(msg, n) -> list:
    splitted_len = (len(msg) // n + 1) * n if len(msg) % n != 0 else len(msg)
    msg = msg.zfill(splitted_len)
    splitted = ''.join([str(get_order(letter)).zfill(3) for letter in msg])
    return [splitted[i * n : (i + 1) * n] for i in range(3 * splitted_len // n)]

def fast_modular_pow(number, power, module):
    bit_power_len = len(bin(power)) - 2
    terms_mod = []
    terms_mod.append(number % module)
    for i in range(bit_power_len + 1):
        terms_mod.append(terms_mod[-1] ** 2 % module)

    output = 1
    for i in range(bit_power_len):
        if (1 << i) & power:
            output *= terms_mod[i]
            output = output % module

    return output


def encrypt(msg, e, n) -> list:
    block_len = get_block_length(n)
    splitted = split(msg, block_len)
    encoded = [fast_modular_pow(int(element), e, n) for element in splitted]
    return encoded

def decrypt(msg, e, p, q) -> str:
    d = generate_secret_key(e, p, q)
    block_len = get_block_length(n)
    decoded = ''
    for el in msg:
        decoded += str(fast_modular_pow(el, d, n)).zfill(block_len)
    decoded_str = ''.join([get_letter(int(decoded[i * 3 : (i + 1) * 3])) for i in range(len(decoded) // 3)])
    while decoded_str[0] == '0':
        decoded_str = decoded_str[1:]
    return decoded_str

if __name__ == '__main__':
    # p, q = 911, 919
    # p, q = 53, 67
    p, q, e = generate_key(1024)
    n = p * q
    # print(generate_secret_key(e, p, q))
    # print(get_block_length(p,q))
    # print(encrypt('abcde', p, q))
    print(decrypt(encrypt('roman мутель 05-12 !@#$%^&*(', e, n), e, p, q))
