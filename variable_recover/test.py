import ctypes

# l = [25652525, 1,2,3]
# print(hex(l[0]))
# print(hex(x))
# h = hex(x)
# print(h)

# z = ctypes.c_int32(x).value
# print(z)
# print(hex(z))
#
# y = x.to_bytes(4, byteorder='little').decode()
# print(y)
'''
s = "adasd"
with open("a.txt", 'a') as f:
    f.write(s + "\n")
    # f.write("\n")
# a = bytearray(x)
# print(a)
for x in l:
    b = x.to_bytes(8, byteorder='big')
    print(b)
    print(list(b))
    # for i in list(b):
    #     print("%02d"%i, end=" ")
    with open("a.txt", 'a') as f:
        for i in list(b):
            f.write("%02x"%i + " ")
        f.write("\n")
# y = bytearray(b)
# print(y)
# print(list(y))
'''



a = 1
b = 2
c = "dasda"
l = [a, b, c]
# l.append(a)
# l.append(b)
# l.append(c)

for i in l:
    if isinstance(i, str):
        print(i)

















