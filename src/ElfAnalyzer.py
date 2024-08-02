import logging

from elftools.elf.elffile import ELFFile
import os


class ElfAnalyzer:

    def __init__(self, elfpath: str):
        self.elfpath = elfpath

    def __enter__(self):
        self.open_elf()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_elf()
        if exc_type is not None:
            logging.exception(exc_val)

    def open_elf(self):
        self.elf = ELFFile(open(self.elfpath, 'rb'))

    def close_elf(self):
        self.elf.close()

    #get addresses of sections in binary file, for example .bss, .rodata etc.
    def get_section_addresses(self, section_name: str) -> tuple[int, int]:
        section = self.elf.get_section_by_name(section_name)
        start_address = int(section['sh_addr'])
        end_address = start_address + int(section['sh_size'])
        return start_address, end_address

    def is_function_inside_section(self, func_address: int, image_base: int, section_name: str) -> bool:
        start_address, end_address = tuple(map(lambda x: x + image_base, self.get_section_addresses(section_name)))
        return start_address <= func_address < end_address

    #stripped files - files without debugging information
    def is_stripped(self) -> bool:
        file_description = os.popen(f"file {self.elfpath}", "r").readline()
        if "not stripped" in file_description:
            return False
        else:
            return True
