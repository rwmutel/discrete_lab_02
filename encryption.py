'''
Module for RSA encryption by Roman Mutel
'''

def get_letter(order: int) -> str:
    # alphabet length is 144
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' + \
        'АБВГҐДЕЄЖЗИІЇКЛМНОПРСТУФХЦЧШЩЬЮЯабвгґдеєжзиіїйклмнопрстуфхцчшщьюя01234567890!@#$%^&*()_+-=? '
    return alphabet[order]

def get_order(letter: str) -> int:
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' + \
        'АБВГҐДЕЄЖЗИІЇКЛМНОПРСТУФХЦЧШЩЬЮЯабвгґдеєжзиіїйклмнопрстуфхцчшщьюя01234567890!@#$%^&*()_+-=? '
    return alphabet.find(letter)

def gcd(a, b):
    if a % b == 0:
        return b
    return gcd(b, a % b)

def generate_key(p, q):
    n = p * q
    e = 10 # hard coded value
    l = (p - 1) * (q - 1)
    while gcd(l, e) != 1 or e % 2 == 0:
        e += 1
    return p*q, e

def generate_secret_key(e, p, q):
    return _modular_inverse(e, (p - 1)*(q - 1))

def _modular_inverse(a, m):
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

def get_block_length(p, q):
    n = 1
    number = 144 # alphabet length
    while number < p * q:
        number += 144 * 1000 ** n
        n += 1
    return 2 * (n - 1)

def split(msg, n) -> list:
    splitted_len = (len(msg) // n + 1) * n if len(msg) % n != 0 else len(msg)
    msg = msg.zfill(splitted_len)
    splitted = ''.join([str(get_order(letter)).zfill(3) for letter in msg])
    return [splitted[i * n : (i + 1) * n] for i in range(3 * splitted_len // n)]

def encode(msg, p, q) -> list:
    n, e = generate_key(p, q)
    block_len = get_block_length(p, q)
    splitted = split(msg, block_len)
    encoded = [int(element) ** e % n for element in splitted]
    return encoded

def decode(msg, e, p, q) -> str:
    d = generate_secret_key(e, p, q)
    block_len = get_block_length(p, q)
    decoded = ''
    for el in msg:
        decoded += str(el ** d % (p * q)).zfill(block_len)
    decoded_str = ''.join([get_letter(int(decoded[i * 3 : (i + 1) * 3])) for i in range(len(decoded) // 3)])
    while decoded_str[0] == '0':
        decoded_str = decoded_str[1:]
    return decoded_str

if __name__ == '__main__':
    p, q = 911, 919
    # p, q = 53, 67
    e = generate_key(p, q)[1]
    # print(generate_secret_key(e, p, q))
    # print(get_block_length(p,q))
    # print(encode('abcde', p, q))
    print(decode(encode('roman mutel 05-12', p, q), e, p, q))
