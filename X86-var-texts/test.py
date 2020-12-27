import binascii

string1 = b'AAAA'
string2 = b'ZZZZ'
string3 = b'aaaa'
string4 = b'zzzz'

x1 = int(binascii.hexlify(string1), 16)
x2 = int(binascii.hexlify(string2), 16)
x3 = int(binascii.hexlify(string3), 16)
x4 = int(binascii.hexlify(string4), 16)

print(x1)
print(x2)
print(x3)
print(x4)
