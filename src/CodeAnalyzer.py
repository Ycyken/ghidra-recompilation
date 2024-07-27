stack_protectors = ["__stack_chk_fail", "___stack_chk_guard", "in_FS_OFFSET"]

class CodeAnalyzer:
    def __init__(self, signature: str, func_code: str):
        self.func_code = func_code
        self.signature = signature
        self.types_of_variables = {}
        
    def get_variable_name(self, variable: str) -> str:
        if "*" in variable:
                variable = variable[variable.rfind("*")+1:]
        if "[" in variable:
            variable = variable[:variable.find("[")]
        if ";" in variable:
            variable = variable[:variable.find(";")]
        return variable
    
    def get_variables_types_from_signature(self):
        for argument in self.signature[self.signature.find("(")+1:self.signature.find(")")].split(","):
            if argument == "void":
                break
            type, variable = argument.split()
            variable = self.get_variable_name(variable)
            self.types_of_variables[variable] = type
        return self.types_of_variables

    def get_line_without_warnings(self, line: str, warning_in_load: bool, warning_in_store: bool) -> str:
        lvalue, rvalue = line.split(" = ")
        variable = self.get_variable_name(lvalue.strip())
        if warning_in_load:
            if rvalue[1] == "(":
                line = lvalue + " = " + rvalue[0] + f"({self.types_of_variables[variable]} *)" + rvalue[rvalue.index(")")+1:]
            else:
                line = lvalue + " = " + rvalue[0] + f"({self.types_of_variables[variable]} *)" + rvalue[1:]
        
        if warning_in_store:
            if lvalue[1] == "(":
                line = lvalue[0] + f"({self.types_of_variables[variable]} *)" + lvalue[lvalue.index(")")+1:] + " = " + rvalue
            else:
                line = lvalue[0] + f"({self.types_of_variables[variable]} *)" + lvalue[1:] + " = " + rvalue
        return line

    def get_code_without_warnings(self) -> str:
        warning_in_load = False
        warning_in_store = False
        need_to_delete_brace = False

        self.types_of_variables = self.get_variables_types_from_signature()

        lines = self.func_code.split("\n")
        lineID = 0
        while "{" not in lines[lineID]:
            lineID += 1
        lineID += 1

        line = lines[lineID][:lines[lineID].find(" [")].split()
        while len(line) == 2 and line[0] not in ["return", "do"]:
            type, variable = line[0], self.get_variable_name(line[1])
            self.types_of_variables[variable] = type
            lineID += 1
            line = lines[lineID][:lines[lineID].find(" [")].split()
        
        for id in range(lineID, len(lines)):
            if "WARNING: Load size is inaccurate" in lines[id]:
                warning_in_load = True
                continue

            elif "WARNING: Store size is inaccurate" in lines[id]:
                warning_in_store = True
                continue

            elif warning_in_load or warning_in_store:
                lines[id] = self.get_line_without_warnings(lines[id], warning_in_load, warning_in_store)
                warning_in_load, warning_in_store = False, False
                continue

            elif "}" in lines[id] and need_to_delete_brace:
                lines[id] = ""
                need_to_delete_brace = False
                continue

            for protector in stack_protectors:
                if protector in lines[id]:
                    if lines[id].strip()[-1] == "{":
                        need_to_delete_brace = True
                    lines[id] = ""
                    break

        return "\n".join(lines)
