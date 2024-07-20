import pyhidra
import shutil
from src.ElfAnalyzer import ElfAnalyzer

pyhidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressRangeImpl

integer_types = {
    "undefined1": "char",
    "undefined2": "short",
    "undefined3": "int",
    "undefined4": "int",
    "undefined5": "long long",
    "undefined6": "long long",
    "undefined7": "long long",
    "undefined8": "long long",
    "undefined": "char",
}

float_types = {
    "undefined4": "double",
    "undefined8": "double",
    "undefined": "double"
}

static_linked_funcs = ["_init", "_start", "deregister_tm_clones", "register_tm_clones",
                       "__do_global_dtors_aux", "frame_dummy", "_fini", "__libc_start_main",
                       "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__gmon_start__",
                       "__cxa_finalize"]

utypes = {
    "byte": "unsigned char",
    "ulong": "unsigned long",
    "ulonglong": "unsigned long long",
    "uint": "unsigned int",
    "ushort": "unsigned short"
}

libc = ["assert.h", "ctype.h", "complex.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
        "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdarg.h",
        "stdbool.h", "stdint.h", "stddef.h", "stdio.h", "stdlib.h", "string.h", "tgmath.h",
        "threads.h", "time.h", "wchar.h", "wctype.h"]

types_from_libc = {
    "bool": "stdbool.h",
    "complex8": "complex.h",
    "complex16": "complex.h",
    "complex32": "complex.h",
    "doublecomplex": "complex.h",
    "doublecomplex": "complex.h",
    "floatcomplex": "complex.h",
    "longdoublecomplex": "complex.h",
    "wint_t": "wchar.h",
    "wctrans_t": "wchar.h",
    "wctype_t": "wchar.h",
    "fenv_t": "fenv.h",
    "fexcept_t": "fenv.h",
}

floating_point_instructions = ["MOVSS", "MOVSD", "ADDSS", "ADDSD", "SUBSS", "SUBSD", "MULSS", "MULSD",
                               "DIVSS", "DIVSD", "MINSS", "MINSD", "MAXSS", "MAXSD", "SQRTSS", "SQRTSD",
                               "RCPSS", "RCPSD", "RSQRTSS", "RSQRTSD", "CMPSS", "CMPSD", "CMPEQSS", "CMPEQSD",
                               "CMPLTSS", "CMPLTSD", "CMPLESS", "CMPLESD", "CMPNESS", "CMPNESD", "CMPUNORDSS",
                               "CMPUNORDSD", "CMPNLTSS", "CMPNLTSD", "CMPNLESS", "CMPNLESD", "CMPORDSS", "CMPORDSD"]

stack_protectors = ["__stack_chk_fail", "___stack_chk_guard", "in_FS_OFFSET"]


class PostProcessor:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.elfAnalyzer = ElfAnalyzer(filepath)

    def run(self):
        with pyhidra.open_program(self.filepath) as flat_api:
            program = flat_api.getCurrentProgram()

            funcs = program.functionManager.getFunctionsNoStubs(True)
            filtered_funcs = self.filter_funcs(funcs, program)
            decompiled_funcs = self.get_decompiled_funcs(program, filtered_funcs)

            with open(self.filepath + ".c", "w") as file:
                self.write_headers(file, program, decompiled_funcs)
                self.write_global_variables(file, flat_api)
                self.write_funcs(file, filtered_funcs, decompiled_funcs)
        shutil.rmtree(self.filepath + "_ghidra")

    def write_global_variables(self, file, flat_api):
        sections = (".bss", ".data", ".rodata")
        for section_name in sections:
            symbols = self.get_symbols_from_section(flat_api, section_name)
            for symbol in symbols:
                result = self.get_symbol_type_and_value(symbol, flat_api)
                if result is None:
                    continue

                type, value = result
                name = symbol.getName()
                if name[0] == "_" or "std" in name:
                    continue
                correct_name = self.correct_variable_name(name)
                global_var_definition = repr(f"{type} {correct_name} = {value};")[1:-1]
                file.write(global_var_definition + "\n")
        file.write("\n")

    def correct_variable_name(self, name: str) -> str:
        correct_name = ""
        for index, char in enumerate(name, start=1):
            if char.isalpha() or char == "_":
                correct_name += char
            elif char.isdigit() and index != 0:
                correct_name += char
            else:
                correct_name += "_"
        return correct_name

    def get_symbols_from_section(self, flat_api, section_name: str):
        program = flat_api.getCurrentProgram()
        block = program.getMemory().getBlock(section_name)
        start_addr = block.getStart()
        end_addr = block.getEnd()
        addr_range = AddressRangeImpl(start_addr, end_addr)
        symbol_table = program.getSymbolTable()

        symbols_in_section = []
        for addr in addr_range.iterator():
            symbols_at_addr = symbol_table.getSymbols(addr)
            if len(symbols_at_addr) == 0:
                continue
            symbols_in_section.append(symbol_table.getSymbols(addr)[0])
        return symbols_in_section

    def get_symbol_type_and_value(self, symbol, flat_api) -> (str, str):
        program = flat_api.getCurrentProgram()
        listing = program.getListing()
        addr = symbol.getAddress()
        data = listing.getDataAt(addr)
        type = data.getDataType().getName()
        value = data.getValue()
        if self.is_symbol_float(symbol, program):
            type = float_types[type]
            if value is None:
                value = 0
            elif type == "float":
                value = flat_api.getFloat(addr)
            else:
                value = flat_api.getDouble(addr)
        elif type == "pointer":
            type = "void *"
            if value is None:
                value = 0
            else:
                value = int(str(value), 16)
        elif type == "string":
            type = "char *"
            if value is None:
                value = 0
            else:
                value = '\"' + value + '\"'
        else:
            type = integer_types[type]
            if value is None:
                value = 0
            else:
                value = int(str(value), 16)
        return type, str(value)

    def is_symbol_float(self, symbol, program) -> bool:
        listing = program.getListing()
        addr = symbol.getAddress()
        data = listing.getDataAt(addr)
        type = data.getDataType().getName()
        if not ("undefined" in type or "float" in type or "double" in type):
            return False
        for reference in symbol.getReferences():
            addr = reference.getFromAddress()
            code_unit = listing.getCodeUnitContaining(addr)
            if code_unit is None:
                continue
            mnemonic = code_unit.getMnemonicString()
            if mnemonic in floating_point_instructions:
                return True
        return False

    def get_headers_from_ghidra(self, headers, program):
        data_type_manager = program.getDataTypeManager()
        for categoryID in range(data_type_manager.getCategoryCount()):
            header = str(data_type_manager.getCategory(categoryID)).split("/")[1]
            if header in libc:
                headers.add(header)
        return headers

    def get_headers_from_functions(self, headers, decompiled_funcs):
        for func in decompiled_funcs:
            variable_declarations = func.getC().split("{")[1].split(";")

            declarationID = 0
            variable_declaration = variable_declarations[declarationID].split()
            while len(variable_declaration) == 2 and variable_declaration[0] not in ["return", "do"]:
                headers.add(types_from_libc.get(variable_declaration[0]))
                declarationID += 1
                variable_declaration = variable_declarations[declarationID].split()

        return headers

    def get_code_without_stack_protection(self, func_code):
        lines = func_code.split("\n")
        need_to_delete_brace = False

        for id, line in enumerate(lines):
            for protector in stack_protectors:
                if protector in line:
                    if line.strip()[-1] == "{":
                        need_to_delete_brace = True
                    lines[id] = ""
                    continue

                elif "}" in line and need_to_delete_brace:
                    lines[id] = ""
                    need_to_delete_brace = False
        return "\n".join(lines)

    def write_headers(self, file, program, decompiled_funcs):
        headers = set()
        headers = self.get_headers_from_ghidra(headers, program)
        headers = self.get_headers_from_functions(headers, decompiled_funcs)

        for header in headers:
            if header is None:
                continue
            file.write(f"#include<{header}>\n")
        file.write("\n")

    def write_funcs(self, file, funcs, decompiled_funcs):
        for index, func in enumerate(decompiled_funcs):
            if funcs[index].getName() == "main":
                continue
            func_signature = func.getSignature()
            for key in integer_types.keys():
                func_signature = func_signature.replace(key, integer_types[key])
            for key in utypes.keys():
                func_signature = func_signature.replace(key, utypes[key])
            file.write(func_signature + "\n")

        for func in decompiled_funcs:
            func_code = func.getC()
            for protector in stack_protectors:
                if protector in func_code:
                    func_code = self.get_code_without_stack_protection(func_code)
            for key in integer_types.keys():
                func_code = func_code.replace(key, integer_types[key])
            for key in utypes.keys():
                func_code = func_code.replace(key, utypes[key])
            file.write(func_code)

    def get_decompiled_funcs(self, program, funcs):
        ifc = DecompInterface()
        ifc.openProgram(program)
        funcs_decompiled = []
        for f in funcs:
            result = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
            func_decompiled = result.getDecompiledFunction()
            funcs_decompiled.append(func_decompiled)
        return funcs_decompiled

    def filter_funcs(self, funcs, program):
        filtered_funcs = []
        listing = program.getListing()
        for f in funcs:
            if f.getName() in static_linked_funcs or f.isThunk():
                continue

            f_addr = int(str(f.getEntryPoint()), 16)
            program_image_base = int(str(program.getImageBase()), 16)
            if not self.elfAnalyzer.is_function_inside_section(f_addr, program_image_base, ".text"):
                continue

            if self.is_libc_start_main_in_function(f):
                continue
                
            addr_set = f.getBody()
            if not self.is_function_starts_with_endbr(addr_set, listing):
                continue

            if self.is_hlt_in_function(addr_set, listing):
                continue

            if self.elfAnalyzer.is_jump_outside_function(addr_set, listing):
                continue
            filtered_funcs.append(f)
        return filtered_funcs
