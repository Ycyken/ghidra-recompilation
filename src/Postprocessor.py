import pyhidra
import shutil
import logging
from src.ElfAnalyzer import ElfAnalyzer
from src.AssemblyAnalyzer import AssemblyAnalyzer
from src.CodeAnalyzer import CodeAnalyzer
from src.TypeAnalyzer import TypeAnalyzer
from src.TypeAnalyzer import integer_types
from src.TypeAnalyzer import utypes
from src.resources.LibcFunctions import libc_functions
from src.Writer import Writer
from collections import deque

pyhidra.start()
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressRangeImpl
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import DataTypeWriter
from java.io import StringWriter

logger = logging.getLogger(__name__)

static_linked_funcs = ["_init", "_start", "deregister_tm_clones", "register_tm_clones",
                       "__do_global_dtors_aux", "frame_dummy", "_fini", "__libc_start_main",
                       "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__gmon_start__",
                       "__cxa_finalize"]

libc = {"assert.h", "ctype.h", "complex.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
        "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdarg.h",
        "stdbool.h", "stdint.h", "stddef.h", "stdio.h", "stdlib.h", "string.h", "tgmath.h",
        "threads.h", "time.h", "wchar.h", "wctype.h"}

libc_types = {
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
            # stdbool temporary included by default cause types detection in global variables not yet implemented
            self.headers: set[str] = {"stdbool.h"}
            self.transfer_types = set()

            funcs = program.functionManager.getFunctionsNoStubs(True)
            filtered_funcs = self.filter_funcs(funcs)
            decompiled_funcs = self.get_decompiled_funcs(filtered_funcs)
            with open(self.filepath + ".c", "w") as file:
                self.write_headers(file, decompiled_funcs)
                self.write_typedefs_and_structs(file)
                self.write_global_variables(file)
                self.write_funcs(file, filtered_funcs, decompiled_funcs)
        shutil.rmtree(self.filepath + "_ghidra")

    def write_typedefs_and_structs(self, file):
        data_type_manager = self.program.getDataTypeManager()
        string_writer = StringWriter()
        data_types = []
        for data_type in data_type_manager.getAllDataTypes():
            data_name = data_type.getName()
            category_path_name = data_type.getCategoryPath().getName()
            # if data type is not elf-gnu specific and not from headers
            if ("ELF" not in category_path_name and category_path_name not in self.headers
                    and not data_name.startswith("_")):
                data_types.append(data_type)

        data_type_writer = DataTypeWriter(data_type_manager, string_writer)
        data_type_writer.write(data_types, self.flat_api.getMonitor())
        content = string_writer.toString()
        file.write(content)

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

    def detect_datatype_header_dependency(self, data_type: str):
        header = libc_types.get(data_type)
        if header is not None:
            self.headers.add(header)

    def detect_function_header_dependency(self, function_name: str):
        header = libc_functions.get(function_name)
        if header is not None:
            self.headers.add(header)

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
                self.detect_datatype_header_dependency(data_type)

    def write_headers(self, file, decompiled_funcs):
        self.add_headers_from_ghidra()
        self.add_headers_from_functions(decompiled_funcs)

        for header in self.headers:
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
            if "WARNING:" in func_code or "._" in func_code:
                codeAnalyzer = CodeAnalyzer(func.getSignature(), func_code)
                writer = Writer(file)
                func_code = codeAnalyzer.get_correct_code()
                for type in codeAnalyzer.get_transfer_types():
                    if type in self.transfer_types:
                        continue
                    if type == "char_pointer":
                        writer.write_transfer_func_pchar(type)
                    else:
                        writer.write_transfer_func(type)
                    self.transfer_types.add(type)

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
            self.detect_function_header_dependency(f.getName())

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
