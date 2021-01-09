import sys
from variable_recover.variables_value_extractor import VariablesValueExtractor


def main(argv):
    file_name = "rm"

    # X86
    X86_file_path = "/home/qinfan/coreutils/coreutils-X86/src/" + file_name
    X86_save_path = '/home/qinfan/PycharmProjects/angr/X86-var-texts/' + file_name + "_dec.txt"
    X86_data_path = '/home/qinfan/PycharmProjects/angr/data/X86/' + file_name + "_data.txt"

    # ARM32
    ARM32_file_path = "/home/qinfan/coreutils/coreutils-ARM32/src/" + file_name
    ARM32_save_path = '/home/qinfan/PycharmProjects/angr/ARM32-var-texts/' + file_name + "_dec.txt"
    ARM32_data_path = '/home/qinfan/PycharmProjects/angr/data/ARM32/' + file_name + "_data.txt"

    # ARM64
    ARM64_file_path = "/home/qinfan/coreutils/coreutils-ARM64/src/" + file_name
    ARM64_save_path = '/home/qinfan/PycharmProjects/angr/ARM64-var-texts/' + file_name + "_dec.txt"
    ARM64_data_path = '/home/qinfan/PycharmProjects/angr/data/ARM64/' + file_name + "_data.txt"

    # MIPS32
    MIPS32_file_path = "/home/qinfan/coreutils/coreutils-MIPS32/src/" + file_name
    MIPS32_save_path = '/home/qinfan/PycharmProjects/angr/MIPS32-var-texts/' + file_name + "_dec.txt"
    MIPS32_data_path = '/home/qinfan/PycharmProjects/angr/data/MIPS32/' + file_name + "_data.txt"

    # MIPS64
    MIPS64_file_path = "/home/qinfan/coreutils/coreutils-MIPS64/src/" + file_name
    MIPS64_save_path = '/home/qinfan/PycharmProjects/angr/MIPS64-var-texts/' + file_name + "_dec.txt"
    MIPS64_data_path = '/home/qinfan/PycharmProjects/angr/data/MIPS64/' + file_name + "_data.txt"

    # extractor_X86 = VariablesValueExtractor(file_name, X86_file_path, X86_save_path, X86_data_path)  # X86
    # extractor_ARM32 = VariablesValueExtractor(file_name, ARM32_file_path, ARM32_save_path, ARM32_data_path)       # ARM32
    # extractor_ARM64 = VariablesValueExtractor(file_name, ARM64_file_path, ARM64_save_path, ARM64_data_path)       # ARM64
    extractor_MIPS32 = VariablesValueExtractor(file_name, MIPS32_file_path, MIPS32_save_path, MIPS32_data_path)    # MIPS32
    # extractor_MIPS64 = VariablesValueExtractor(file_name, MIPS64_file_path, MIPS64_save_path, MIPS64_data_path)    # MIPS64

    # print("extractor_X86.not_cover:", extractor_X86.not_cover)
    # print("extractor_ARM32.not_cover:", extractor_ARM32.not_cover)
    print("extractor_MIPS32.not_cover:", extractor_MIPS32.not_cover)


if __name__ == '__main__':
    main(sys.argv)
