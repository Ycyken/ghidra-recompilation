import pyhidra

pyhidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from src.ElfAnalyzer import ElfAnalyzer

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
    "ulong": "unsigned long",
    "uint": "unsigned int",
    "ushort": "unsigned short"
}

standart_functions = ["assert.h", "ctype.h", "complex.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
                      "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdarg.h",
                      "stdbool.h", "stdint.h", "stddef.h", "stdio.h", "stdlib.h", "string.h", "tgmath.h",
                      "threads.h", "time.h", "wchar.h", "wctype.h"]


class PostProcessor:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.elfAnalyzer = ElfAnalyzer(filepath)

    def run(self):
        with pyhidra.open_program(self.filepath) as flat_api:
            program = flat_api.getCurrentProgram()
            listing = program.getListing()
            dataTypeManager = program.getDataTypeManager()

            all_funcs = program.functionManager.getFunctionsNoStubs(True)
            funcs_filtered = []

            for f in all_funcs:
                if f.getName() in static_linked_funcs or f.isThunk():
                    continue

                f_addr = int(str(f.getEntryPoint()), 16)
                if not self.elfAnalyzer.is_function_inside_section(f_addr, int(str(program.getImageBase()), 16),
                                                                   ".text"):
                    continue

                addr_set = f.getBody()
                code_units = listing.getCodeUnits(addr_set, True)
                if self.elfAnalyzer.is_jump_outside_function(str(addr_set.getMinAddress()),
                                                             str(addr_set.getMaxAddress()),
                                                             code_units):
                    continue
                funcs_filtered.append(f)

            ifc = DecompInterface()
            ifc.openProgram(program)
            funcs_decompiled = []
            for f in funcs_filtered:
                result = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
                func_decompiled = result.getDecompiledFunction()
                funcs_decompiled.append(func_decompiled)

            file = open(self.filepath + ".c", 'w')

            for categoryID in range(dataTypeManager.getCategoryCount()):
                header = str(dataTypeManager.getCategory(categoryID)).split("/")[1]
                if header in standart_functions:
                    file.write(f"#include<{header}>\n")

            for f in funcs_decompiled:
                func_signature = f.getSignature()
                for key in undefined_types.keys():
                    func_signature = func_signature.replace(key, undefined_types[key])
                for key in utypes.keys():
                    func_signature = func_signature.replace(key, utypes[key])
                file.write(func_signature + "\n")

            for f in funcs_decompiled:
                func_code = f.getC()
                for key in undefined_types.keys():
                    func_code = func_code.replace(key, undefined_types[key])
                for key in utypes.keys():
                    func_code = func_code.replace(key, utypes[key])
                file.write(func_code)

            file.close()
