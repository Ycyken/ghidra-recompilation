import pyhidra
import shutil
import logging
from src.ElfAnalyzer import ElfAnalyzer
from src.AssemblyAnalyzer import AssemblyAnalyzer
from src.CodeAnalyzer import CodeAnalyzer
from src.TypeAnalyzer import TypeAnalyzer
from src.TypeAnalyzer import integer_types
from src.TypeAnalyzer import utypes
from collections import deque

pyhidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressRangeImpl
from ghidra.program.model.symbol import SourceType

logger = logging.getLogger(__name__)

static_linked_funcs = ["_init", "_start", "deregister_tm_clones", "register_tm_clones",
                       "__do_global_dtors_aux", "frame_dummy", "_fini", "__libc_start_main",
                       "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__gmon_start__",
                       "__cxa_finalize"]

libc = {"assert.h", "ctype.h", "complex.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
        "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdarg.h",
        "stdbool.h", "stdint.h", "stddef.h", "stdio.h", "stdlib.h", "string.h", "tgmath.h",
        "threads.h", "time.h", "wchar.h", "wctype.h"}

types_from_libc = {
    "bool": "stdbool.h",
    "complex8": "complex.h",
    "complex16": "complex.h",
    "complex32": "complex.h",
    "doublecomplex": "complex.h",
    "floatcomplex": "complex.h",
    "longdoublecomplex": "complex.h",
    "wint_t": "wchar.h",
    "wctrans_t": "wchar.h",
    "wctype_t": "wchar.h",
    "fenv_t": "fenv.h",
    "fexcept_t": "fenv.h",
}

definitions_from_libc = {
    "__ctype_b_loc": "ctype.h",
    "__ctype_tolower_loc": "ctype.h",
    "__ctype_toupper_loc": "ctype.h",
    "_tolower": "ctype.h",
    "_toupper": "ctype.h",
    "isalnum": "ctype.h",
    "isalnum_l": "ctype.h",
    "isalpha": "ctype.h",
    "isalpha_l": "ctype.h",
    "isascii": "ctype.h",
    "isblank": "ctype.h",
    "isblank_l": "ctype.h",
    "iscntrl": "ctype.h",
    "iscntrl_l": "ctype.h",
    "isdigit": "ctype.h",
    "isdigit_l": "ctype.h",
    "isgraph": "ctype.h",
    "isgraph_l": "ctype.h",
    "islower": "ctype.h",
    "islower_l": "ctype.h",
    "isprint": "ctype.h",
    "isprint_l": "ctype.h",
    "ispunct": "ctype.h",
    "ispunct_l": "ctype.h",
    "isspace": "ctype.h",
    "isspace_l": "ctype.h",
    "isupper": "ctype.h",
    "isupper_l": "ctype.h",
    "isxdigit": "ctype.h",
    "isxdigit_l": "ctype.h",
    "toascii": "ctype.h",
    "tolower": "ctype.h",
    "tolower_l": "ctype.h",
    "toupper": "ctype.h",
    "toupper_l": "ctype.h",

    "strerror_r": "string.h",
    "__xpg_strerror_r": "string.h",
    "bzero": "string.h",
    "memset": "string.h",
    "__memcpy_chk": "string.h",
    "__memmove_chk": "string.h",
    "__mempcpy": "string.h",
    "__mempcpy_chk": "string.h",
    "__memset_chk": "string.h",
    "__stpcpy": "string.h",
    "__stpcpy_chk": "string.h",
    "__stpncpy_chk": "string.h",
    "__strcat_chk": "string.h",
    "__strcpy_chk": "string.h",
    "__strncat_chk": "string.h",
    "__strncpy_chk": "string.h",
    "__strtok_r": "string.h",
    "memccpy": "string.h",
    "memchr": "string.h",
    "memcmp": "string.h",
    "memcpy": "string.h",
    "memmem": "string.h",
    "memmove": "string.h",
    "memrchr": "string.h",
    "stpcpy": "string.h",
    "stpncpy": "string.h",
    "strcasestr": "string.h",
    "strcat": "string.h",
    "strchr": "string.h",
    "strcmp": "string.h",
    "strcoll": "string.h",
    "strcoll_l": "string.h",
    "strcpy": "string.h",
    "strcspn": "string.h",
    "strdup": "string.h",
    "strerror": "string.h",
    "strerror_l": "string.h",
    "strlen": "string.h",
    "strncat": "string.h",
    "strncmp": "string.h",
    "strncpy": "string.h",
    "strndup": "string.h",
    "strnlen": "string.h",
    "strpbrk": "string.h",
    "strrchr": "string.h",
    "strsep": "string.h",
    "strsignal": "string.h",
    "strspn": "string.h",
    "strstr": "string.h",
    "strtok": "string.h",
    "strtok_r": "string.h",
    "strxfrm": "string.h",
    "strxfrm_l": "string.h"
}

floating_point_instructions = ["MOVSS", "MOVSD", "ADDSS", "ADDSD", "SUBSS", "SUBSD", "MULSS", "MULSD",
                               "DIVSS", "DIVSD", "MINSS", "MINSD", "MAXSS", "MAXSD", "SQRTSS", "SQRTSD",
                               "RCPSS", "RCPSD", "RSQRTSS", "RSQRTSD", "CMPSS", "CMPSD", "CMPEQSS", "CMPEQSD",
                               "CMPLTSS", "CMPLTSD", "CMPLESS", "CMPLESD", "CMPNESS", "CMPNESD", "CMPUNORDSS",
                               "CMPUNORDSD", "CMPNLTSS", "CMPNLTSD", "CMPNLESS", "CMPNLESD", "CMPORDSS", "CMPORDSD"]


class PostProcessor:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def run(self):
        with pyhidra.open_program(self.filepath) as flat_api, ElfAnalyzer(self.filepath) as elfAnalyzer:
            program = flat_api.getCurrentProgram()
            self.elfAnalyzer = elfAnalyzer
            self.typeAnalyzer = TypeAnalyzer(flat_api)
            self.flat_api = flat_api
            self.program = program
            self.headers = set()

            funcs = program.functionManager.getFunctionsNoStubs(True)
            filtered_funcs = self.filter_funcs(funcs)
            decompiled_funcs = self.get_decompiled_funcs(filtered_funcs)
            with open(self.filepath + ".c", "w") as file:
                self.write_headers(file, decompiled_funcs)
                self.write_global_variables(file)
                self.write_funcs(file, filtered_funcs, decompiled_funcs)
        shutil.rmtree(self.filepath + "_ghidra")

    def write_global_variables(self, file):
        sections = (".bss", ".data", ".rodata")
        for section_name in sections:
            symbols = self.get_symbols_from_section(section_name)
            for symbol in symbols:
                result = self.typeAnalyzer.get_symbol_type_and_value(symbol)
                if result is None:
                    continue

                data_type, value = result
                name = symbol.getName()
                if name[0] == "_" or "std" in name:
                    continue
                correct_name = self.correct_variable_name(name)
                data_type, correct_name = self.typeAnalyzer.correct_array_type_declaration(data_type, correct_name)
                global_var_definition = ""
                if value is None:
                    global_var_definition = repr(f"{data_type} {correct_name};")[1:-1]
                else:
                    global_var_definition = repr(f"{data_type} {correct_name} = {value};")[1:-1]
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

    def get_symbols_from_section(self, section_name: str):
        block = self.program.getMemory().getBlock(section_name)
        start_addr = block.getStart()
        end_addr = block.getEnd()
        addr_range = AddressRangeImpl(start_addr, end_addr)
        symbol_table = self.program.getSymbolTable()

        symbols_in_section = []
        for addr in addr_range.iterator():
            symbols_at_addr = symbol_table.getSymbols(addr)
            if len(symbols_at_addr) >= 1:
                symbols_in_section.append(symbol_table.getSymbols(addr)[0])
        return symbols_in_section

    def add_headers_from_ghidra(self):
        data_type_manager = self.program.getDataTypeManager()
        for categoryID in range(data_type_manager.getCategoryCount()):
            category = data_type_manager.getCategory(categoryID)
            if category is None:
                continue
            header = str(category).split("/")[-1]
            if header in libc:
                self.headers.add(header)

    def add_headers_from_functions(self, decompiled_funcs):
        for func in decompiled_funcs:
            func_code = func.getC()
            codelines = func_code.split("{")[1].split(";")

            for codeline in codelines:
                declaration = codeline[:codeline.find("[")].split()
                if len(declaration) != 2:
                    continue
                data_type = declaration[0]
                header = types_from_libc.get(data_type)
                if header is not None:
                    self.headers.add(header)

    def write_headers(self, file, decompiled_funcs):
        self.add_headers_from_ghidra()
        self.add_headers_from_functions(decompiled_funcs)

        for header in self.headers:
            if header is None:
                continue
            file.write(f"#include <{header}>\n")
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
            func_signature = func_signature.replace(".", "_")
            file.write(func_signature + "\n")

        for func in decompiled_funcs:
            func_code = func.getC()
            if "WARNING:" in func_code:
                codeAnalyzer = CodeAnalyzer(func.getSignature(), func_code)
                func_code = codeAnalyzer.get_code_without_warnings()

            for key in integer_types.keys():
                func_code = func_code.replace(key, integer_types[key])
            for key in utypes.keys():
                func_code = func_code.replace(key, utypes[key])
            file.write(func_code)

    def get_decompiled_funcs(self, funcs):
        ifc = DecompInterface()
        options = DecompileOptions()
        options.setSimplifyDoublePrecision(True)
        ifc.setOptions(options)
        ifc.openProgram(self.program)
        funcs_decompiled = []
        for f in funcs:
            result = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
            if not result.decompileCompleted():
                logger.warning("function %s was not decompiled: %s", f.getName(), result.getErrorMessage())
                continue

            func_decompiled = result.getDecompiledFunction()
            funcs_decompiled.append(func_decompiled)
        return funcs_decompiled

    def filter_funcs(self, funcs):
        filtered_funcs = []
        for f in funcs:
            self.headers.add(definitions_from_libc.get(f.getName()))

            if f.getName() in static_linked_funcs or f.isThunk():
                continue

            f_addr = int(str(f.getEntryPoint()), 16)
            program_image_base = int(str(self.program.getImageBase()), 16)
            if not self.elfAnalyzer.is_function_inside_section(f_addr, program_image_base, ".text"):
                continue

            addr_set = f.getBody()
            assemly_analyzer = AssemblyAnalyzer(addr_set, self.program.getListing())
            if assemly_analyzer.is_function_nonuser():
                continue

            filtered_funcs.append(f)

        main = self.find_main(filtered_funcs)
        if main is None:
            logger.error("Can't find main function")
        main_call_tree = self.get_call_tree(main)

        # filter funcs again by being in the main call tree
        filtered_funcs = list(filter(lambda a: a in main_call_tree, filtered_funcs))
        return filtered_funcs

    def get_call_tree(self, function):
        monitor = self.flat_api.getMonitor()
        call_tree = {function}
        not_visited = deque([function])

        while len(not_visited) > 0:
            f = not_visited.pop()
            for called_func in f.getCalledFunctions(monitor):
                if called_func not in call_tree:
                    not_visited.append(called_func)
                    call_tree.add(called_func)
        return call_tree

    def find_main(self, funcs):
        for f in funcs:
            if f.getName() == "main":
                return f

        if not self.elfAnalyzer.is_stripped():
            return None

        monitor = self.flat_api.getMonitor()
        _start = None
        for f in self.program.functionManager.getFunctionsNoStubs(True):
            if f.getName() == "entry":
                _start = f
                break
        if _start is None:
            return None

        _start_called_funcs = _start.getCalledFunctions(monitor)
        main = None
        for f in _start_called_funcs:
            if f.getName() != "__libc_start_main":
                main = f
                main.setName("main", SourceType.USER_DEFINED)
                break
        return main
