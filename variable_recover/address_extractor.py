import sys
# add temporary environment variables path of pyelftools root home
# sys.path[0:0] = ['.', '..', 'D:\\VMShare\\pyelftools-master', '/mnt/hgfs/VMShare/pyelftools-master']
from collections import defaultdict

from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import re
import os
from copy import deepcopy


class VariablesAddressExtractor:

    def __init__(self, fstream, save_fpath):
        """
        Initialization of VariablesAddressExtractor class
        Args:
            fstream: ELF File stream;
            save_fpath: address result file path;
        """

        self.elffile = ELFFile(fstream)
        self.save_fpath = save_fpath
        if os.path.exists(self.save_fpath):
            print('[VariablesAddressExtractor] {} already exists, removed!'.format(self.save_fpath))
            os.remove(self.save_fpath)

        self.func_data = list()
        self.func_names = list()
        self.max_struct_prefix = 10

        self.variables_offset = defaultdict(list)

    def parse_address(self):
        """
        main method entrance of VariablesAddressExtractor class
        """
        self.parse_dwarf()
        code_section = self.elffile.get_section_by_name('.text')
        code_byte = code_section.data()
        section_address = code_section['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        disasm_addr_pattern = re.compile(r"([-+]{1}\s*\w*)\]", re.DOTALL | re.MULTILINE)
        func_info = None
        lowpc, highpc = -1, -1
        rax = -1
        for address, size, mnemonic, op_str in md.disasm_lite(code_byte, section_address):
            if address < lowpc or address >= highpc:
                if func_info:
                    self.save_func_info(func_info)
                    varl = []
                    self.func_names.append(func_info['func_name'])
                    for var in func_info['variables']:
                        varl = [var['variable_name'], var['variable_offset']]
                        self.variables_offset[func_info['func_name']].append(varl)
                    # print(func_info['func_name'])
                    # for var in func_info['variables']:
                    #     print(var['variable_name'], var['variable_offset'])

                func_info = self._get_func_info(address)
            if func_info != None:
                lowpc, highpc = func_info['lowpc'], func_info['highpc']
            else:
                continue
            op_list = op_str.split(',')
            for idx, op in enumerate(op_list):
                if "rbp" in op and "[" in op:
                    address_offset = disasm_addr_pattern.findall(op)[0].replace(' ', '')
                    address_offset = int(address_offset, 16)
                    if "rax" in op_str: rax = address_offset
                    for variable in func_info['variables']:
                        variable_offset = variable['variable_offset']
                        variable_byte_size = variable['byte_size']
                        if variable_offset <= address_offset and variable_byte_size + variable_offset > address_offset:
                            variable['variable_address'].append((hex(address), '0'))
                    for parameter in func_info['parameters']:
                        parameter_offset = parameter['variable_offset']
                        parameter_byte_size = parameter['byte_size']
                        if parameter_offset <= address_offset and parameter_byte_size + parameter_offset > address_offset:
                            parameter['variable_address'].append((hex(address), '0'))
                elif idx == 0 and "rax" in op and "[" in op:
                    variable_addr = op.replace("[", "").replace("]", "")
                    result = disasm_addr_pattern.findall(variable_addr)
                    address_offset = rax
                    for variable in func_info['variables']:
                        variable_offset = variable['variable_offset']
                        variable_byte_size = variable['byte_size']
                        if variable_offset <= address_offset and variable_byte_size + variable_offset > address_offset:
                            variable['variable_address'].append((hex(address), '1'))
                    for parameter in func_info['parameters']:
                        parameter_offset = parameter['variable_offset']
                        parameter_byte_size = parameter['byte_size']
                        if parameter_offset <= address_offset and parameter_byte_size + parameter_offset > address_offset:
                            parameter['variable_address'].append((hex(address), '1'))

    def _get_func_info(self, address):
        """
        helper function of `parse_address`
        Args:
            address: instructions address, decimal;
        Returns:
            If the given instructions address in a function's address range, 
            then return this function information `func_info`, else return None.
            format of func_info:
                 {'func_name': function name, 'highpc': highpc, 'lowpc': lowpc, 
                    'return_type': return type, 'variables': function variables,
                    'parameters': function parameters}
        """
        if not self.func_data: self.parse_dwarf()
        for func_info in self.func_data:
            if func_info['lowpc'] <= address < func_info['highpc']:
                func_info_copy = {}
                for k, v in func_info.items():
                    if k == 'subprogram_DIE': continue
                    func_info_copy[k] = deepcopy(v)
                variables, parameters = self.parse_variables_parameters(func_info['subprogram_DIE'])
                func_info_copy['variables'] = variables
                func_info_copy['parameters'] = parameters
                return func_info_copy
        return None

    def save_func_info(self, func_info):
        """
        write function information into save file
        Args:
            func_info: function information with variabels address;
        """
        with open(self.save_fpath, 'a+') as f:
            f.write('{}\t{}\t{}\t'.format(func_info['func_name'],
                                          func_info['return_type'], hex(func_info['lowpc'])))
            f.write('{}\t'.format(len(func_info['parameters'])))
            for parameter in func_info['parameters']:
                f.write('{}\t{}\t{}\t{}\t'.format(parameter['variable_type'],
                                                  parameter['variable_name'], parameter['member_location'],
                                                  len(parameter['variable_address']), ))
                for address, i in parameter['variable_address']:
                    f.write('{}\t{}\t'.format(address, i))
            f.write('{}\t'.format(len(func_info['variables'])))
            for variable in func_info['variables']:
                f.write('{}\t{}\t{}\t{}\t'.format(variable['variable_type'],
                                                  variable['variable_name'], variable['member_location'],
                                                  len(variable['variable_address']), ))
                for address, i in variable['variable_address']:
                    f.write('{}\t{}\t'.format(address, i))
            f.write('\n')

    def parse_dwarf(self):
        """
        Parse dwarf information, contains:
            1. function name
            2. return type
            3. lowpc of function
            3. highpc of function
            4. subprogram DIE, which for subsequent variables and paramters parsing.
        """
        self.dwarf_info = self.elffile.get_dwarf_info()
        location_lists = self.dwarf_info.location_lists()
        self.loc_parser = LocationParser(location_lists)
        for CU in self.dwarf_info.iter_CUs():
            self._CU = CU
            for DIE in CU.iter_DIEs():
                self._DIE = DIE
                if DIE.tag != 'DW_TAG_subprogram': continue
                # 1. parse function name
                func_name = bytes2str(DIE.attributes['DW_AT_name'].value)
                # 2. parse lowpc
                lowpc = DIE.attributes['DW_AT_low_pc'].value
                # 3. parse highpc
                highpc_attr = DIE.attributes['DW_AT_high_pc']
                highpc_attr_class = describe_form_class(highpc_attr.form)
                if highpc_attr_class == 'address':
                    highpc = highpc_attr.value
                elif highpc_attr_class == 'constant':
                    highpc = lowpc + highpc_attr.value
                # 4. parse function return type
                if 'DW_AT_type' in DIE.attributes:
                    type_die = DIE.get_DIE_from_attribute("DW_AT_type")
                    return_type = self.parse_type(type_die)
                else:
                    return_type = 'void'
                func_info = {'func_name': func_name, 'highpc': highpc, 'lowpc': lowpc,
                             'return_type': return_type, 'variables': [],
                             'parameters': [], 'subprogram_DIE': DIE}
                self.func_data.append(func_info)

    def parse_type(self, type_die):
        """
        get the type name of type die, direct return or recursive.
        Args:
            type_die: the type die.
        Returns:
            A type name of this type die.
        Raise:
            Unimplemented Error: Unknown type die.
        """
        if type_die.tag == 'DW_TAG_base_type':
            return bytes2str(type_die.attributes['DW_AT_name'].value)
        elif type_die.tag == 'DW_TAG_typedef':
            if 'DW_AT_type' not in type_die.attributes:
                return bytes2str(type_die.attributes['DW_AT_name'].value)
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die)
        elif type_die.tag == 'DW_TAG_const_type':
            if 'DW_AT_type' not in type_die.attributes: return 'void'
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die)
        elif type_die.tag == 'DW_TAG_subroutine_type':
            if 'DW_AT_type' not in type_die.attributes: return 'void'
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die)
        elif type_die.tag == 'DW_TAG_structure_type':
            if 'DW_AT_name' not in type_die.attributes: return 'void'
            return bytes2str(type_die.attributes['DW_AT_name'].value)
        elif type_die.tag == 'DW_TAG_pointer_type':
            if 'DW_AT_type' not in type_die.attributes: return 'void'
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die) + ' *'
        elif type_die.tag == 'DW_TAG_enumeration_type':
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die)
        elif type_die.tag == 'DW_TAG_array_type':
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die) + ' *'
        elif type_die.tag == 'DW_TAG_union_type':
            return 'union'
        elif type_die.tag == 'DW_TAG_restrict_type':
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die)
        elif type_die.tag == 'DW_TAG_volatile_type':
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.parse_type(new_type_die)
        else:
            print(type_die)
            raise Exception('parse_type: Unimplemented situation: {}'.format(type_die.tag))

    def parse_variables_parameters(self, DIE):
        """
        parse function variables and parameters, considering 4 DIE situation:
            1. DW_TAG_lexical_block for sub code block
            2. DW_TAG_variable for variable
            3. DW_TAG_formal_parameter for parameter
            4. DW_TAG_label, maybe for go to statement
        """
        variables = []
        parameters = []
        for child_die in DIE.iter_children():
            if child_die.tag == "DW_TAG_lexical_block":
                v, p = self.parse_variables_parameters(child_die)
                variables += v
                parameters += p
            if 'DW_AT_location' not in child_die.attributes: continue
            if child_die.tag == "DW_TAG_variable":
                for variable_info in self._parse_variable(child_die):
                    if variable_info: variables.append(variable_info)
            elif child_die.tag == "DW_TAG_formal_parameter":
                for parameter_info in self._parse_variable(child_die):
                    if parameter_info: parameters.append(parameter_info)
            elif child_die.tag == "DW_TAG_label":
                continue
            else:
                continue
        return variables, parameters

    def _parse_variable(self, var_die):
        """
        helper function of `parse_variables_parameters`, parsing variable or parameter.
        In special, the struct variable(or parameter) should paring thier member variable.
        Args:
            var_die: the DIE of variable or parameter.
        Yield:
            variable(or parameter) information `vaiable_info`
            format of `variable_info`:
                {'variable_name': varaibale name, 'variable_offset': variable address offset relative to funciton lowpc, 
                    'variable_type': variable type, 'byte_size': variable byte size, 
                    'variable_address': empty list for subsequent address parsing,
                    'member_location': -1 if not struct member variable}
        """
        type_die = var_die.get_DIE_from_attribute("DW_AT_type")
        var_type = self.parse_type(type_die)
        var_name = bytes2str(var_die.attributes['DW_AT_name'].value)
        location_attr = var_die.attributes['DW_AT_location']
        location = self.loc_parser.parse_from_attribute(location_attr, self._CU['version'])
        byte_size = self.get_byte_size(type_die)
        s = describe_DWARF_expr(location.loc_expr, self.dwarf_info.structs, self._CU.cu_offset)
        if 'DW_OP_fbreg' not in s: return
        variable_offset = int(re.findall(r'[-\d]+', s)[0]) + 0x10

        # self.variables_offset[var_name] = variable_offset

        if not self._is_base_type(type_die):
            for member_info in self.parse_struct(var_die, variable_offset): yield member_info
        yield {'variable_name': var_name, 'variable_offset': variable_offset,
               'variable_type': var_type, 'byte_size': byte_size, 'variable_address': [],
               'member_location': -1}

    def parse_struct(self, var_die, variable_offset, prefixs=None, struct_names=None):
        """
        parsing structure variable, considering Nested structure, using recursion.
        Special Situations: structure member is structure itself.
        Args:
            var_die: structure variable DIE;
            variable_offset: structure variable address offset;
            prefixs: parents structure variable name.
            struct_names: parents structure name.
        Yield:
            member information `member_info`
            format of `member_info` as smae as `varaible_info`.
        """
        if not prefixs: prefixs = []; struct_names = []
        var_name = bytes2str(var_die.attributes['DW_AT_name'].value)
        prefixs.append(var_name)
        if len(prefixs) >= self.max_struct_prefix: return
        struct_die = self._get_struct_type_die(var_die)
        if 'DW_AT_name' in struct_die.attributes:
            struct_name = bytes2str(struct_die.attributes['DW_AT_name'].value)
            if struct_name in struct_names:
                return
            else:
                struct_names.append(struct_name)
        for child_die in struct_die.iter_children():
            if child_die.tag != 'DW_TAG_member':  continue
            if 'DW_AT_name' not in child_die.attributes: continue
            if 'DW_AT_data_member_location' not in child_die.attributes: continue
            member_name = bytes2str(child_die.attributes['DW_AT_name'].value)
            member_type_die = child_die.get_DIE_from_attribute("DW_AT_type")
            member_location = child_die.attributes["DW_AT_data_member_location"].value
            if self._is_base_type(member_type_die):
                prefixs_copy = prefixs.copy()
                prefixs_copy.append(member_name)
                var_name = '.'.join(prefixs_copy)
                var_type = self.parse_type(member_type_die)
                byte_size = self.get_byte_size(member_type_die)
                member_info = {'variable_name': var_name, 'variable_offset': variable_offset,
                               'variable_type': var_type, 'byte_size': byte_size, 'variable_address': [],
                               'member_location': member_location}
                yield member_info
            else:
                for member_info in self.parse_struct(child_die, variable_offset + member_location,
                                                     prefixs.copy(), struct_names.copy()):
                    yield member_info

    def _is_base_type(self, type_die):
        """
        helper function of `parse_struct`, tell if the given type_die is base type or not.
        Considering pointer type, using recursion.
        Args:
            type_die: the type DIE.
        Returns:
            return True if the given type_die is base type else False.
        """
        if type_die.tag == 'DW_TAG_base_type':
            return True
        elif type_die.tag == 'DW_TAG_typedef':
            if 'DW_AT_type' not in type_die.attributes: return False
            return self._is_base_type(type_die.get_DIE_from_attribute("DW_AT_type"))
        elif type_die.tag == 'DW_TAG_const_type':
            if 'DW_AT_type' not in type_die.attributes: return False
            return self._is_base_type(type_die.get_DIE_from_attribute("DW_AT_type"))
        elif type_die.tag == 'DW_TAG_subroutine_type':
            return False
        elif type_die.tag == 'DW_TAG_structure_type':
            return False
        elif type_die.tag == 'DW_TAG_pointer_type':
            if 'DW_AT_type' not in type_die.attributes: return False
            return self._is_base_type(type_die.get_DIE_from_attribute("DW_AT_type"))
        elif type_die.tag == 'DW_TAG_enumeration_type':
            return False
        elif type_die.tag == 'DW_TAG_array_type':
            return self._is_base_type(type_die.get_DIE_from_attribute("DW_AT_type"))
        else:
            return False

    def _get_struct_type_die(self, var_die):
        """
        helper function of `parse_struct`.
        Considering DW_TAG_typedef, DW_TAG_pointer_type, DW_TAG_array_type and else, using recursion to get 
            structure DIE of the given structure variabe DIE.
        Args:
            var_die: variable DIE.
        Returns:
            structure DIE of the given structure variabe DIE.
        """
        if var_die.tag in ['DW_TAG_variable', 'DW_TAG_formal_parameter', 'DW_TAG_member']:
            type_die = var_die.get_DIE_from_attribute("DW_AT_type")
        else:
            type_die = var_die
        if type_die.tag == 'DW_TAG_structure_type': return type_die
        if type_die.tag == 'DW_TAG_union_type': return var_die
        if type_die.tag == 'DW_TAG_enumeration_type':
            return type_die
        elif type_die.tag == 'DW_TAG_typedef':
            if 'DW_AT_type' not in type_die.attributes: return type_die
            return self._get_struct_type_die(type_die.get_DIE_from_attribute("DW_AT_type"))
        elif type_die.tag == 'DW_TAG_pointer_type':
            if 'DW_AT_type' not in type_die.attributes: return type_die
            return self._get_struct_type_die(type_die.get_DIE_from_attribute("DW_AT_type"))
        elif type_die.tag == 'DW_TAG_array_type':
            if 'DW_AT_type' not in type_die.attributes: print(type_die)
            return self._get_struct_type_die(type_die.get_DIE_from_attribute("DW_AT_type"))
        else:
            return var_die
            # raise Exception('_get_struct_type_die: Unimplemented situation  {}'.format(type_die.tag))

    def get_byte_size(self, type_die):
        """
        A helper funciton to get the size of the given type DIE.
        Args:
            type_die: type DIE.
        Returns:
            the byte size of the given type DIE.
        """
        if 'DW_AT_byte_size' in type_die.attributes:
            return type_die.attributes['DW_AT_byte_size'].value
        elif 'DW_AT_type' in type_die.attributes:
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_type")
            return self.get_byte_size(new_type_die)
        elif 'DW_AT_abstract_origin' in type_die.attributes:
            new_type_die = type_die.get_DIE_from_attribute("DW_AT_abstract_origin")
            return self.get_byte_size(new_type_die)
        else:
            return 0


if __name__ == "__main__":
    import time

    start_time = time.time()

    file_path = "/home/qinfan/coreutils/coreutils-8.32/src/basename"
    save_path = '../X86-var-texts/basenaem_g01.txt'
    with open(file_path, 'rb') as f:
        extractor = VariablesAddressExtractor(f, save_path)
        extractor.parse_address()

    print(extractor.variables_offset)
    print(extractor.func_names)
    print(len(extractor.func_names))
    # print(extractor.get_variables_offset())
    # print(extractor.func_data)

    print('time cost: {:.2f} s'.format(time.time() - start_time))
