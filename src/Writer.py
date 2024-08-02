#This class writes special functions for passing bytes
class Writer:
    def __init__(self, file):
        self.file = file

    def write_transfer_func(self, type):
        self.file.write(f"void transfer_value_from_{type.replace(" ", "_")}" +
                        f"(void *to, {type} from, int start, int size)\n")
        self.file.write("{\n")
        self.file.write("  memmove(to + start, (const void*)&from, size);\n")
        self.file.write("}\n")
        self.file.write("\n")

    def write_transfer_func_pchar(self, type):
        self.file.write(f"void transfer_value_from_{type.replace(" ", "_")}" +
                        "(void *to, const void *from, int from_start, int to_start, int size)\n")
        self.file.write("{\n")
        self.file.write("  memmove(to + to_start, from + from_start, size);\n")
        self.file.write("}\n")
        self.file.write("\n")
