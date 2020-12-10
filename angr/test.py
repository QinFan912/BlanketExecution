a = [1, 2, 3]
b = a[:]
print(id(a))
print(id(b))

b.append(5)
print(a)
print(b)