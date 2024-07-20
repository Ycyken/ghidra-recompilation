from elftools.elf.elffile import ELFFile


class ElfAnalyzer:
    def __init__(self, elfpath: str):
        elf = ELFFile(open(elfpath, 'rb'))
        self.elf = elf

    def get_section_addresses(self, section_name: str) -> tuple[int, int]:
        section = self.elf.get_section_by_name(section_name)
        start_address = int(section['sh_addr'])
        end_address = start_address + int(section['sh_size'])
        return start_address, end_address

    def is_function_inside_section(self, func_address: int, image_base: int, section_name: str) -> bool:
        start_address, end_address = tuple(map (lambda x : x + image_base, self.get_section_addresses(section_name)))
        return start_address <= func_address < end_address
