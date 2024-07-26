stack_protectors = ["__stack_chk_fail", "___stack_chk_guard", "in_FS_OFFSET"]

class CodeAnalyzer:
    def __init__(self, func_code):
        self.func_code = func_code
        
    def get_variable_name(self, variable):
        if "*" in variable:
                variable = variable[variable.rfind("*")+1:]
        if "[" in variable:
            variable = variable[:variable.find("[")]
        if ";" in variable:
            variable = variable[:variable.find(";")]
        return variable
    
    def get_variables_types_from_signature(self, lines, types_of_variables):
        for argument in lines[1][lines[1].find("(")+1:lines[1].find(")")].split(","):
            if argument == "void":
                continue
            type, variable = argument.split()
            variable = self.get_variable_name(variable)
            types_of_variables[variable] = type
        return types_of_variables

    def get_variables_types_from_code(self, lines, types_of_variables):
        id = 4
        variable_declaration = lines[id].split()
        while len(variable_declaration) == 2 and variable_declaration[0] not in ["return", "do"]:
            type, variable = variable_declaration
            variable = self.get_variable_name(variable)
            types_of_variables[variable] = type
            id += 1
            variable_declaration = lines[id].split()
        return types_of_variables

    def remove_warnings(self, lines, id, warning_in_load, warning_in_store, types_of_variables):
        lvalue, rvalue = lines[id].split(" = ")
        variable = self.get_variable_name(lvalue.strip())
        if warning_in_load:
            if rvalue[1] == "(":
                lines[id] = lvalue + " = " + rvalue[0] + f"({types_of_variables[variable]} *)" + rvalue[rvalue.index(")")+1:]
            else:
                lines[id] = lvalue + " = " + rvalue[0] + f"({types_of_variables[variable]} *)" + rvalue[1:]
        
        if warning_in_store:
            if lvalue[1] == "(":
                lines[id] = lvalue[0] + f"({types_of_variables[variable]} *)" + lvalue[lvalue.index(")")+1:] + " = " + rvalue
            else:
                lines[id] = lvalue[0] + f"({types_of_variables[variable]} *)" + lvalue[1:] + " = " + rvalue

    def get_code_without_warnings(self):
        lines = self.func_code.split("\n")
        warning_in_load = False
        warning_in_store = False
        need_to_delete_brace = False

        types_of_variables = {}
        types_of_variables = self.get_variables_types_from_signature(lines, types_of_variables)
        types_of_variables = self.get_variables_types_from_code(lines, types_of_variables)
        
        for id, line in enumerate(lines):
            if "WARNING: Load size is inaccurate" in line:
                warning_in_load = True
                continue

            elif "WARNING: Store size is inaccurate" in line:
                warning_in_store = True
                continue

            elif warning_in_load or warning_in_store:
                self.remove_warnings(lines, id, warning_in_load, warning_in_store, types_of_variables)
                warning_in_load, warning_in_store = False, False
                continue

            elif "}" in line and need_to_delete_brace:
                lines[id] = ""
                need_to_delete_brace = False
                continue

            for protector in stack_protectors:
                if protector in line:
                    if line.strip()[-1] == "{":
                        need_to_delete_brace = True
                    lines[id] = ""
                    break

        return "\n".join(lines)