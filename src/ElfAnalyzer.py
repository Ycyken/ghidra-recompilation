from elftools.elf.elffile import ELFFile


class ElfAnalyzer:
    def __init__(self, elfpath: str):
        elf = ELFFile(open(elfpath, 'rb'))
        self.elf = elf

    def is_function_inside_section(self, func_address: int, image_base: int, section_name: str) -> bool:
        section = self.elf.get_section_by_name(section_name)
        start_address = int(section['sh_addr']) + image_base
        end_address = start_address + int(section['sh_size']) + image_base
        return start_address <= func_address < end_address

    @staticmethod
    def is_jump_outside_function(start_address: str, end_address: str, code_units):
        for code_unit in code_units:
            code_unit_string = str(code_unit)
            jmp_address = ""
            length_of_code_unit_string = len(code_unit_string)
            if length_of_code_unit_string < 3 or code_unit_string[:3] != "JMP":
                continue

            for i in range(length_of_code_unit_string):
                if code_unit_string[i].isdigit() and i < (length_of_code_unit_string - 9):
                    jmp_address += code_unit_string[i]
                    for j in range(i + 1, i + 10):
                        jmp_address += code_unit_string[j]
                    break

            if (len(jmp_address) > 0 and (
                    int(start_address, 16) > int(jmp_address, 16) or int(jmp_address, 16) > int(end_address, 16))):
                return True
        return False
