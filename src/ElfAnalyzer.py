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

    @staticmethod
    def is_jump_outside_function(addr_set, listing):
        start_address = int(str(addr_set.getMinAddress()), 16)
        end_address = int(str(addr_set.getMaxAddress()), 16)
        code_units = listing.getCodeUnits(addr_set, False)
        
        for code_unit in code_units:
            if str(code_unit.getMnemonicString()) != "JMP":
                continue

            destination_address = int(str(code_unit.getPrimaryReference(0).getToAddress()), 16)

            if start_address > destination_address or destination_address > end_address:
                return True
        return False
