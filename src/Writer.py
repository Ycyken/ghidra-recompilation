class Writer:
    def __init__(self, file):
        self.file = file

    def write_transfer_func(self, type):
        self.file.write(f"void transfer_value_from_{type.replace(" ", "_")}(char *to, {type} from, int start, int size)\n")
        self.file.write("{\n")
        self.file.write("  char *p = (char *)&from;\n")
        self.file.write("  for (int i = start; i < start + size; ++i)\n")
        self.file.write("  {\n")
        self.file.write("    to[i] = *p;\n")
        self.file.write("    ++p;\n")
        self.file.write("  }\n")
        self.file.write("}\n")
        self.file.write("\n")

    def write_transfer_func_pchar(self, type):
        self.file.write(f"void transfer_value_from_{type.replace(" ", "_")}(char *to, char *from, int from_start, int to_start, int to_size)\n")
        self.file.write("{\n")
        self.file.write("  int j = from_start;\n")
        self.file.write("  for (int i = to_start; i < to_start + to_size; ++i)\n")
        self.file.write("  {\n")
        self.file.write("    to[i] = from[j];\n")
        self.file.write("    ++j;\n")
        self.file.write("  }\n")
        self.file.write("}\n")
        self.file.write("\n")
