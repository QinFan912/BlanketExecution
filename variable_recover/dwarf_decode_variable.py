#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys

from elftools.dwarf.locationlists import LocationExpr, LocationParser

sys.path[0:0] = ['.', '..']

from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class, describe_DWARF_expr
from elftools.elf.elffile import ELFFile


loc_parser = []

def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print(' file has no DWARF info')
            return

        dwarfinfo = elffile.get_dwarf_info()
        proces_variable_infunction(dwarfinfo,0x4000000)



def get_byte_size(type_die):
    if 'DW_AT_byte_size' in type_die.attributes:
       return type_die.attributes['DW_AT_byte_size'].value
    elif 'DW_AT_type' in type_die.attributes:
       child_type_die = type_die.attributes["DW_AT_type"]
       return  get_byte_size(child_type_die)
    else:
       try:
           child_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")
           return get_byte_size(child_type_die)
       except Exception:
          return 0



def proces_variable_infunction(dwarfinfo,address):
    # 解析dwarf中的单元
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            location_lists = dwarfinfo.location_lists()
            loc_parser.append(LocationParser(location_lists))
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    function_name = bytes2str(DIE.attributes['DW_AT_name'].value)
                    print("function name:%s" % function_name)

                    if function_name == 'main':
                        if DIE.has_children:
                            for child_dire in DIE.iter_children():
                                # 如果是变量类型
                                if child_dire.tag == "DW_TAG_variable":
                                    if 'DW_AT_type' in child_dire.attributes:
                                        type_die = child_dire.attributes["DW_AT_type"]
                                    else:
                                        type_die = child_dire.attributes["DW_AT_abstract_origin"]


                                    if 'DW_AT_name' in child_dire.attributes:
                                        variable_name = child_dire.attributes['DW_AT_name'].value
                                        variable_name = bytes2str(variable_name)
                                    else:
                                        variable_name = ""
                                    print(f"变量名称 % s" % variable_name)
                                    attr = child_dire.attributes['DW_AT_location']

                                    if loc_parser[0].attribute_has_location(attr, CU['version']):

                                        loc = loc_parser[0].parse_from_attribute(attr, CU['version'])
                                        if isinstance(loc, LocationExpr):
                                            # byte_size = get_byte_size(type_die)
                                            s = describe_DWARF_expr(loc.loc_expr,
                                                                    dwarfinfo.structs)
                                            attr = int(s.split(":")[1].replace(")", ""))
                                            attr = attr + 0x10
                                            attr_hex = hex(attr)
                                            print(f"%s变量地址是%s" % (variable_name,attr_hex))
                                        # return variable_name

                    # lowpc = DIE.attributes['DW_AT_low_pc'].value
                    # highpc_attr = DIE.attributes['DW_AT_high_pc']
                    # highpc_attr_class = describe_form_class(highpc_attr.form)
                    # if highpc_attr_class == 'address':
                    #     highpc = highpc_attr.value
                    # elif highpc_attr_class == 'constant':
                    #     highpc = lowpc + highpc_attr.value
                    # else:
                    #     print('Error: invalid DW_AT_high_pc class:',
                    #           highpc_attr_class)
                    #     continue
                    #
                    # # 地址在 lowpc 和 highpc之间
                    # if lowpc <= address <= highpc:
                    #     print(f"function name%s" % DIE.attributes['DW_AT_name'])
            except KeyError:
                continue





if __name__ == '__main__':
    file_path = "/home/qinfan/coreutils/coreutils-8.32/src/basename"
    process_file(file_path)