import os

# failed: tee split who

binary_root = "../trex-datasets/bin"

binaries = []

for arches in os.listdir(binary_root):
    print(arches)
    for dirs in os.listdir(os.path.join(binary_root, arches)):
        print(dirs)
        for binary in os.listdir(os.path.join(binary_root, arches, dirs)):
            print(binary)
            binaries.append(binary)
            print(os.path.join(binary_root, arches, dirs, binary))

print(binaries)
print(len(binaries))

# for i in binaries:
#     print(i)

