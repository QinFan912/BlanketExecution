import sys
import os
import time
from func_timeout import func_set_timeout
import gc

from variable_recover.variables_value_extractor import VariablesValueExtractor


def main(file_name, file_path):
    print("binary {} start executing!".format(file_name))

    extractor = VariablesValueExtractor(file_name, file_path)

    print("extractor.not_cover:", extractor.not_cover)


if __name__ == '__main__':
    binary_root = "../trex-datasets/bin"

    for arches in os.listdir(binary_root):
        for dirs in os.listdir(os.path.join(binary_root, arches)):
            for binary in os.listdir(os.path.join(binary_root, arches, dirs)):
                binary_path = os.path.join(binary_root, arches, dirs, binary)
                print(binary_path)
                t_start = time.time()
                main(binary, binary_path)
                t_end = time.time()
                print("consume {}s".format(t_end - t_start))
                gc.collect()
                os.remove(os.path.join(binary_root, arches, dirs, binary))
                print(f"remove binary: {binary_path} successful!")
                time.sleep(30)


