# -------------------------------------------------------------------------------
# elftools example: dwarf_decode_address.py
#
# Decode an address in an ELF file to find out which function it belongs to
# and from which filename/line it comes in the original source file.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import print_function
import sys
import re
import traceback
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)

func2asse = {}
loc_parser = []

dwarfinfo = []
CUs = {}


def process_file(filename, address):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        pattern = re.compile(r"[-+]{1}\s*\w*$", re.DOTALL | re.MULTILINE)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return
        code = elffile.get_section_by_name(".text")
        ops = code.data()
        addr = code["sh_addr"]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        dwarfinfo.append(elffile.get_dwarf_info())
        for CU in dwarfinfo[0].iter_CUs():
            CUs.update({CU: []})
            for DIE in CU.iter_DIEs():
                # 未访问到
                CUs[CU].append([DIE, False])
        location_lists = dwarfinfo[0].location_lists()
        loc_parser.append(LocationParser(location_lists))
        rax = -1
        # i = dwarfinfo.debug_line_sec
        # a = int("aa51",16)
        # a= ""
        # a.__contains__()
        for i in md.disasm(ops, addr):
            # if i.address< a:
            #     continue

            asse = f"{i.mnemonic}\t{i.op_str}"
            # if asse.__contains__("cvtss2sd"):
            #     continue
            addr1 = hex(i.address)
            # print(f"{addr1}:\t{asse}")

            # get_dwarf_info returns a DWARFInfo context object, which is the
            # starting point for all DWARF-based processing in pyelftools.
            variables, params, return_type, funcname = decode_funcname(i.address)

            file, line = decode_file_line(i.address)
            if funcname != None and file != None and line != None:

                if funcname not in func2asse:
                    func2asse.update({funcname: [return_type, params, variables]})
                file = bytes2str(file)
                # rax =-1
                func2asse[funcname].append({"assembly": (addr1, asse), "file": file, "file_line": line})

                if func2asse[funcname][2] != None:
                    op_strs = i.op_str.split(",")
                    for k, oo in zip(op_strs, range(0, len(op_strs))):
                        if k.__contains__("rbp") and k.__contains__("["):

                            variable_addr = k.replace("[", "").replace("]", "")
                            result = pattern.findall(variable_addr)
                            # print(variable_addr,"\t",result)
                            offset = result[0].replace(" ", "")

                            offset = int(offset, 16)
                            if i.op_str.__contains__("rax"):
                                rax = offset

                            # if funcname == "quotearg_char" and addr1 == '0xaa51':
                            #     print()
                            for variable in func2asse[funcname][2]:
                                variable_offset = variable[2][1]
                                variable_byte_size = variable[2][2]
                                if variable_offset <= offset and variable_byte_size + variable_offset > offset:
                                    variable[3].append((addr1, 0, asse))

                            for param in func2asse[funcname][1]:
                                param_offset = param[2][1]
                                param_byte_size = param[2][2]
                                if param_offset <= offset and param_offset + param_byte_size > offset:
                                    param[3].append((addr1, 0, asse))
                        elif oo == 0 and k.__contains__("rax") and k.__contains__("["):

                            variable_addr = k.replace("[", "").replace("]", "")
                            result = pattern.findall(variable_addr)
                            if result.__len__() == 0:
                                offset = rax
                            else:
                                # offset = result[0].replace(" ", "")
                                # offset = int(offset, 16)
                                offset = rax
                            for variable in func2asse[funcname][2]:
                                variable_offset = variable[2][1]
                                variable_byte_size = variable[2][2]
                                if variable_offset <= offset and variable_byte_size + variable_offset > offset:
                                    variable[3].append((addr1, 1, asse))

                            for param in func2asse[funcname][1]:
                                param_offset = param[2][1]
                                param_byte_size = param[2][2]
                                if param_offset <= offset and param_offset + param_byte_size > offset:
                                    param[3].append((addr1, 1, asse))

                # print('Function:', funcname)
                # print('File:', file)
                # print('Line:', line)
            # print("\n")


def decode_funcname(address):
    # Go over all DIEs in the DWARF information, looking for a subprogram
    # entry with an address range that includes the given address. Note that
    # this simplifies things by disregarding subprograms that may have
    # split address ranges.
    for CU in CUs.keys():
        for DIE_tuple, k in zip(CUs[CU], range(len(CUs[CU]))):
            # print(DIE_tuple,k)
            DIE = DIE_tuple[0]
            is_need_skip = DIE_tuple[1]
            if is_need_skip:
                continue
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    lowpc = DIE.attributes['DW_AT_low_pc'].value

                    # DWARF v4 in section 2.17 describes how to interpret the
                    # DW_AT_high_pc attribute based on the class of its form.
                    # For class 'address' it's taken as an absolute address
                    # (similarly to DW_AT_low_pc); for class 'constant', it's
                    # an offset from DW_AT_low_pc.
                    highpc_attr = DIE.attributes['DW_AT_high_pc']
                    highpc_attr_class = describe_form_class(highpc_attr.form)
                    if highpc_attr_class == 'address':
                        highpc = highpc_attr.value
                    elif highpc_attr_class == 'constant':
                        highpc = lowpc + highpc_attr.value
                    else:
                        print('Error: invalid DW_AT_high_pc class:',
                              highpc_attr_class)
                        continue

                    if lowpc <= address < highpc:
                        variables = None
                        params = None
                        return_type = None
                        fun_name = None
                        try:
                            fun_name = DIE.attributes['DW_AT_name'].value
                            if fun_name != None:
                                fun_name = bytes2str(fun_name)

                                # print(fun_name)
                                # if fun_name != "hash_delete":
                                #     return variables, params, return_type, fun_name
                                if fun_name not in func2asse:
                                    variables = []
                                    params = []
                                    die_info_rec(DIE, params, variables, CU)
                                    type_die = DIE.get_DIE_from_attribute("DW_AT_type")

                                    return_type = decode_type(type_die, [], "-0x10", -0x10)



                        except Exception:
                            return_type = "void"

                        # child_indent = indent_level + '  '
                        # for child in DIE.iter_children():
                        #     die_info_rec(child, child_indent)
                        return variables, params, return_type, fun_name
            except KeyError as e:
                # print(traceback.format_exc())
                continue
            finally:
                # if k-1>=0:
                #     CUs[CU][k-1][1]=True
                pass

    return None, None, None, None


def die_info_rec(die, params, varibles, CU):
    """ A recursive function for showing information about a DIE and its
        children.
    """

    for child in die.iter_children():
        if child.tag == "DW_TAG_variable":
            try:
                if 'DW_AT_type' in child.attributes:
                    type_die = child.get_DIE_from_attribute("DW_AT_type")
                else:
                    type_die = child.get_DIE_from_attribute("DW_AT_abstract_origin")

                # variable_type = child.get_DIE_from_attribute("DW_AT_type").attributes[
                #     'DW_AT_name'].value
                if 'DW_AT_name' in child.attributes:
                    variable_name = child.attributes['DW_AT_name'].value
                    variable_name = bytes2str(variable_name)
                else:
                    variable_name = ""
                # variable_type = bytes2str(variable_type)
                # type_die = child.get_DIE_from_attribute("DW_AT_type")

                attr = child.attributes['DW_AT_location']
                # variable_type = child.get_DIE_from_attribute("DW_AT_location")
                if loc_parser[0].attribute_has_location(attr, CU['version']):
                    # print('   DIE %s. attr %s.' % (DIE.tag, attr.name))
                    loc = loc_parser[0].parse_from_attribute(attr,
                                                             CU['version'])
                    # We either get a list (in case the attribute is a
                    # reference to the .debug_loc section) or a LocationExpr
                    # object (in case the attribute itself contains location
                    # information).

                    if isinstance(loc, LocationExpr):
                        byte_size = get_byte_size(type_die)
                        s = describe_DWARF_expr(loc.loc_expr,
                                                dwarfinfo[0].structs, CU.cu_offset)
                        attr = int(s.split(":")[1].replace(")", ""))
                        attr = attr + 0x10
                        attr_hex = hex(attr)
                    # attr_high = attr + byte_size
                    #  attr_high = hex(attr_high)
                variable_type = decode_type(type_die, varibles, attr_hex, attr, name=variable_name)
                varibles.append((variable_type, variable_name, (attr_hex, attr, byte_size, -1), []))
            except Exception:
                print(traceback.format_exc())
        elif child.tag == 'DW_TAG_formal_parameter':
            try:
                if 'DW_AT_type' in child.attributes:
                    type_die = child.get_DIE_from_attribute("DW_AT_type")
                else:
                    type_die = child.get_DIE_from_attribute("DW_AT_abstract_origin")

                # param_type = type_die.attributes['DW_AT_name'].value
                if 'DW_AT_name' in child.attributes:
                    param_name = child.attributes['DW_AT_name'].value
                    # param_type = bytes2str(param_type)
                    param_name = bytes2str(param_name)
                else:
                    param_name = ""
                # param_name = child.attributes['DW_AT_name'].value
                # # param_type = bytes2str(param_type)
                # param_name = bytes2str(param_name)
                # location_die = child.attributes['DW_AT_location'].value
                attr = child.attributes['DW_AT_location']
                # variable_type = child.get_DIE_from_attribute("DW_AT_location")
                if loc_parser[0].attribute_has_location(attr, CU['version']):
                    # print('   DIE %s. attr %s.' % (DIE.tag, attr.name))
                    loc = loc_parser[0].parse_from_attribute(attr,
                                                             CU['version'])
                    # We either get a list (in case the attribute is a
                    # reference to the .debug_loc section) or a LocationExpr
                    # object (in case the attribute itself contains location
                    # information).
                    # byte_size = 0
                    byte_size = get_byte_size(type_die)
                    if isinstance(loc, LocationExpr):
                        s = describe_DWARF_expr(loc.loc_expr,
                                                dwarfinfo[0].structs, CU.cu_offset)
                        attr = int(s.split(":")[1].replace(")", ""))
                        attr = attr + 0x10
                        # attr_high = attr + byte_size
                        # attr_high = hex(attr_high)
                        attr_hex = hex(attr)
                param_type = decode_type(type_die, params, attr_hex, attr, name=param_name)
                params.append((param_type, param_name, (attr_hex, attr, byte_size, -1), []))
            except Exception:
                print(traceback.format_exc())
        else:
            if child.tag == 'DW_TAG_lexical_block':
                die_info_rec(child, params, varibles, CU)


def get_byte_size(type_die):
    if 'DW_AT_byte_size' in type_die.attributes:
        return type_die.attributes['DW_AT_byte_size'].value
    elif 'DW_AT_type' in type_die.attributes:
        child_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
        return get_byte_size(child_type_die)
    else:
        try:
            child_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")
            return get_byte_size(child_type_die)
        except Exception:
            return 0


base_type = ["int", "char", "float", "long double", "long int", "long long int", "long long unsigned int",
             "long unsigned int", "short int", "short unsigned int", "signed char", "unsigned int", "unsigned char"]


def decode_type_point(type_die, varibles, attr_hex, attr, point="", pre="", name="", pre_bytes=0):
    if type_die.tag == "DW_TAG_array_type":
        return "void"
    if 'DW_AT_name' not in type_die.attributes:
        if type_die.tag == 'DW_TAG_pointer_type':
            point = point + "*"
        try:
            type_die1 = type_die.get_DIE_from_attribute("DW_AT_type")
            return decode_type_point(type_die1, varibles, attr_hex, attr, point, pre, name)

        except Exception:
            return "void " + point
            print(traceback.format_exc())
        # else:
        # return point
    else:

        if type_die.has_children:

            # if pre != "":
            #     pre = pre + "." + bytes2str(type_die.attributes['DW_AT_name'].value)
            # else:
            #     pre = name +"."+bytes2str(type_die.attributes['DW_AT_name'].value)
            if not pre.count(".") > 100:
                bytes_start = pre_bytes
                for child in type_die.iter_children():
                    if 'DW_AT_name' in child.attributes:
                        child_type_die = None
                        if 'DW_AT_type' in child.attributes:
                            child_type_die = child.get_DIE_from_attribute("DW_AT_type")
                        elif "DW_AT_abstract_origin" in child.attributes:
                            child_type_die = child.get_DIE_from_attribute("DW_AT_abstract_origin")
                        else:
                            try:
                                child_type_die = child.get_DIE_from_attribute("'DW_AT_const_value'")
                            except Exception:
                                pass  # print()
                        if child_type_die == None:
                            continue
                        name_h = bytes2str(child.attributes['DW_AT_name'].value)
                        if pre != "":
                            struct_arr = pre.split(".")
                            if name_h not in struct_arr:
                                pre1 = pre + "." + name_h
                            else:
                                return "void"
                        else:
                            if name != "":
                                pre1 = name + "." + bytes2str(child.attributes['DW_AT_name'].value)
                            else:
                                pre1 = bytes2str(child.attributes['DW_AT_name'].value)

                        # chengyuan_type =None
                        bytes = get_byte_size(child_type_die)  # child_type_die.attributes['DW_AT_byte_size'].value
                        # if 'DW_AT_name' in child_type_die.attributes:
                        #     if child.attributes['DW_AT_name'][1] == 'DW_FORM_strp':
                        #         name_ = bytes2str(child.attributes['DW_AT_name'][2])
                        #         if name_ not in base_type:
                        #             chengyuan_type = ""
                        #
                        # if chengyuan_type ==None:
                        bytes_start = pre_bytes + child.attributes["DW_AT_data_member_location"].value
                        chengyuan_type = decode_type_point(child_type_die, varibles, attr_hex, attr, "", pre1,
                                                           pre_bytes=bytes_start)

                        varibles.append((chengyuan_type, pre1,
                                         (attr_hex, attr, bytes, bytes_start), []))
                        # bytes_start = bytes_start+bytes
                        # attr = attr + bytes
                    # varibles.append()#chengyuan.append(type+"|"+bytes2str(child.attributes['DW_AT_name'].value)+"|"+str(child.attributes['DW_AT_data_member_location'].value))
            # if 'DW_AT_type' in type_die.attributes:
            #     child_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            #     return decode_type(child_type_die, varibles, attr_hex, attr, "", pre,pre_bytes= pre_bytes)
            # elif "DW_AT_abstract_origin" in type_die.attributes:
            #     child_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")
            #     return decode_type(child_type_die, varibles,attr_hex, attr, "", pre,pre_bytes= pre_bytes)
            if point != "":
                return bytes2str(type_die.attributes['DW_AT_name'].value) + " " + point
            else:

                return bytes2str(type_die.attributes['DW_AT_name'].value)

        elif 'DW_AT_type' in type_die.attributes:

            child_type_die = type_die.get_DIE_from_attribute("DW_AT_type")

            return decode_type_point(child_type_die, varibles, attr_hex, attr, pre=pre, pre_bytes=pre_bytes,
                                     point=point, name=name)

        elif "DW_AT_abstract_origin" in type_die.attributes:

            child_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")

            return decode_type_point(child_type_die, varibles, attr_hex, attr, pre=pre, pre_bytes=pre_bytes,
                                     point=point, name=name)
        elif point != "":

            return bytes2str(type_die.attributes['DW_AT_name'].value) + " " + point
        else:

            return bytes2str(type_die.attributes['DW_AT_name'].value)


def decode_type(type_die, varibles, attr_hex, attr, point="", pre="", name=""):
    if type_die.tag == "DW_TAG_array_type":
        return "void"
    if 'DW_AT_name' not in type_die.attributes:
        if type_die.tag == 'DW_TAG_pointer_type':
            point = point + "*"
        try:
            type_die1 = type_die.get_DIE_from_attribute("DW_AT_type")
            return decode_type_point(type_die1, varibles, attr_hex, attr, point, pre, name)

        except Exception:
            print(traceback.format_exc())
            return "void " + point

        # else:
        # return point
    else:

        if type_die.has_children:

            # if pre != "":
            #     pre = pre + "." + bytes2str(type_die.attributes['DW_AT_name'].value)
            # else:
            #     pre = name +"."+bytes2str(type_die.attributes['DW_AT_name'].value)
            if not pre.count(".") > 100:
                for child in type_die.iter_children():
                    if 'DW_AT_name' in child.attributes:
                        child_type_die = None
                        if 'DW_AT_type' in child.attributes:
                            child_type_die = child.get_DIE_from_attribute("DW_AT_type")
                        elif "DW_AT_abstract_origin" in child.attributes:
                            child_type_die = child.get_DIE_from_attribute("DW_AT_abstract_origin")
                        else:
                            try:
                                child_type_die = child.get_DIE_from_attribute("'DW_AT_const_value'")
                            except Exception:
                                pass  # print()
                        if child_type_die == None:
                            continue
                        if pre != "":
                            pre1 = pre + "." + bytes2str(child.attributes['DW_AT_name'].value)
                        else:

                            if name != "":
                                pre1 = name + "." + bytes2str(child.attributes['DW_AT_name'].value)
                            else:
                                pre1 = bytes2str(child.attributes['DW_AT_name'].value)

                        bytes = get_byte_size(child_type_die)  # child_type_die.attributes['DW_AT_byte_size'].value

                        # chengyuan_type =None
                        # if 'DW_AT_name' in child.attributes:
                        #     if child.attributes['DW_AT_name'][1] == 'DW_FORM_strp':
                        #         name_ = bytes2str(child.attributes['DW_AT_name'][2])
                        #         if name_ not in base_type:
                        #            chengyuan_type = ""
                        # if chengyuan_type==None:
                        bytes_start = child.attributes["DW_AT_data_member_location"].value
                        chengyuan_type = decode_type(child_type_die, varibles, attr_hex, attr + bytes_start, "", pre1)

                        varibles.append((chengyuan_type, pre1,
                                         (attr_hex, attr + bytes_start, bytes, -1), []))
                        # attr = attr + bytes

                    # varibles.append()#chengyuan.append(type+"|"+bytes2str(child.attributes['DW_AT_name'].value)+"|"+str(child.attributes['DW_AT_data_member_location'].value))
            # if 'DW_AT_type' in type_die.attributes:
            #     child_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            #     return decode_type(child_type_die, varibles,attr_hex, attr, "", pre)
            # elif "DW_AT_abstract_origin" in type_die.attributes:
            #     child_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")
            #     return decode_type(child_type_die, varibles, attr_hex, attr, "", pre)
            if point != "":

                return bytes2str(type_die.attributes['DW_AT_name'].value) + " " + point
            else:

                return bytes2str(type_die.attributes['DW_AT_name'].value)

        elif 'DW_AT_type' in type_die.attributes:
            child_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return decode_type(child_type_die, varibles, attr_hex, attr, pre=pre, point=point, name=name)
        elif "DW_AT_abstract_origin" in type_die.attributes:
            child_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")
            return decode_type(child_type_die, varibles, attr_hex, attr, pre=pre, point=point, name=name)
        elif point != "":

            return bytes2str(type_die.attributes['DW_AT_name'].value) + " " + point
        else:

            return bytes2str(type_die.attributes['DW_AT_name'].value)


def decode_file_line(address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo[0].iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo[0].line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            if entry.state.end_sequence:
                # if the line number sequence ends, clear prevstate.
                prevstate = None
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return filename, line
            prevstate = entry.state
    return None, None


def save2txt(dict, file_name):
    f = open("test_save.dic")
    dict = eval(f.read())
    f.close()
    f1 = open(file_name, "w")

    for key in dict.keys():
        print(key, dict[key][0])
        f1.write(key)
        f1.write("\t")
        f1.write(dict[key][0])
        f1.write("\t")
        f1.write(dict[key][3]["assembly"][0])
        f1.write("\t")
        f1.write(str(len(dict[key][1])))
        f1.write("\t")
        for param in dict[key][1]:
            print("param:", param[0], param[1], str(len(param[3])), param[2][3])
            f1.write(param[0])
            f1.write("\t")
            f1.write(param[1])
            f1.write("\t")
            f1.write(str(param[2][3]))
            f1.write("\t")
            f1.write(str(len(param[3])))
            f1.write("\t")
            for addr in param[3]:
                f1.write(addr[0])
                f1.write("\t")
                f1.write(str(addr[1]))
                f1.write("\t")
        f1.write(str(len(dict[key][2])))
        f1.write("\t")
        for var in dict[key][2]:
            print("var:", var[0], var[1], str(len(var[3])), var[2][3])
            print(var)
            f1.write(var[0])
            f1.write("\t")
            f1.write(var[1])
            f1.write("\t")
            f1.write(str(var[2][3]))
            f1.write("\t")
            f1.write(str(len(var[3])))
            f1.write("\t")
            for addr in var[3]:
                f1.write(addr[0])
                f1.write("\t")
                f1.write(str(addr[1]))
                f1.write("\t")

        f1.write("\n")
    print(dict)
    f1.close()


import os

if __name__ == '__main__':
    # python dwarf_decode_address.py ../tools/bin/cp ../tools/parsed/cp
    # with open("../tools/bin/cp", "rb") as f:
    #     e = ELFFile(f)
    #     # for section in e.iter_sections():
    #     #     print(hex(section["sh_addr"]),section.name)
    # file_path = sys.argv[1]
    # save_path = sys.argv[2]
    # file_path = "../8.23/bin/cp"
    # save_path = "../8.23/parsed/cp.txt"
    file_path = "../test.elf"
    save_path = "./test_save.txt"
    print(file_path, save_path)
    process_file(file_path, 0)
    save2txt(func2asse, save_path)

    # process_file("../tools/bin/cp",0)
    # f = open("cp_save.dic","w")
    # f.write(str(func2asse))
    # f.close()
