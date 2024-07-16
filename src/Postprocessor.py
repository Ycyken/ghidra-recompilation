import pyhidra
import shutil
from src.ElfAnalyzer import ElfAnalyzer

pyhidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

undefined_types = {
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
                self.write_funcs(file, filtered_funcs, decompiled_funcs)
        shutil.rmtree(self.filepath + "_ghidra")

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
        
    def write_headers(self, file, program, decompiled_funcs):
        headers = set()
        headers = self.get_headers_from_ghidra(headers, program)
        headers = self.get_headers_from_functions(headers, decompiled_funcs)

        for header in headers:
            if header == None:
                continue
            file.write(f"#include<{header}>\n")
        file.write("\n")

    def write_funcs(self, file, funcs, decompiled_funcs):
        for index, func in enumerate(decompiled_funcs):
            if funcs[index].getName() == "main":
                continue
            func_signature = func.getSignature()
            for key in undefined_types.keys():
                func_signature = func_signature.replace(key, undefined_types[key])
            for key in utypes.keys():
                func_signature = func_signature.replace(key, utypes[key])
            file.write(func_signature + "\n")

        for func in decompiled_funcs:
            func_code = func.getC()
            for key in undefined_types.keys():
                func_code = func_code.replace(key, undefined_types[key])
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

            addr_set = f.getBody()
            code_units = listing.getCodeUnits(addr_set, True)
            if self.elfAnalyzer.is_jump_outside_function(str(addr_set.getMinAddress()),
                                                         str(addr_set.getMaxAddress()),
                                                         code_units):
                continue
            filtered_funcs.append(f)
        return filtered_funcs
