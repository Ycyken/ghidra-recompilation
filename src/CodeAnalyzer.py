from src.TypeAnalyzer import utypes
from src.TypeAnalyzer import integer_types

stack_protectors = ["__stack_chk_fail", "___stack_chk_guard", "in_FS_OFFSET"]

types_sizes = {
    "1": "char",
    "2": "short",
    "4": "int",
    "8": "long long"
}


class CodeAnalyzer:
    def __init__(self, signature: str, func_code: str):
        self.func_code = func_code
        self.signature = signature
        self.types_of_variables = {}
        self.transfer_types = set()

    def get_transfer_types(self):
        return self.transfer_types

    def get_variable_name(self, variable: str) -> str:
        if "*" in variable:
            variable = variable[variable.rfind("*") + 1:]
        if "[" in variable:
            variable = variable[:variable.find("[")]
        if ";" in variable:
            variable = variable[:variable.find(";")]
        if ")" in variable:
            variable = variable[:variable.find(")")]
        return variable

    def get_variables_types_from_signature(self) -> dict:
        for argument in self.signature[self.signature.find("(") + 1:self.signature.find(")")].split(","):
            if argument == "void" or argument == "...":
                break
            type, variable = argument.split()
            variable = self.get_variable_name(variable)
            self.types_of_variables[variable] = type
        return self.types_of_variables

    def get_line_without_warnings(self, line: str, warning_in_load: bool, warning_in_store: bool) -> str:
        if " = " not in line:
            return line
        lvalue, rvalue = line.split(" = ")
        variable = self.get_variable_name(lvalue.strip())
        if warning_in_load:
            if rvalue[1] == "(":
                line = (lvalue + " = " + rvalue[0] + f"({self.types_of_variables[variable]} *)" +
                        rvalue[rvalue.index(")") + 1:])
            else:
                line = (lvalue + " = " + rvalue[0] + f"({self.types_of_variables[variable]} *)" +
                        rvalue[1:])

        if warning_in_store:
            if lvalue[1] == "(":
                line = lvalue[0] + f"({self.types_of_variables[variable]} *)" + lvalue[
                                                                                lvalue.index(")") + 1:] + " = " + rvalue
            else:
                line = lvalue[0] + f"({self.types_of_variables[variable]} *)" + lvalue[1:] + " = " + rvalue
        return line

    def get_variable_and_id(self, line: str, id: int) -> {str, int}:
        variable = ""

        while line[id].isalnum() or line[id] == "_" or line[id] == "." or line[id] == "'":
            variable = line[id] + variable
            id -= 1

        return variable, id

    def get_variable_attribute_and_id(self, line: str, id: int) -> {str, int}:
        attribute = ""

        while line[id].isdigit():
            attribute += line[id]
            id += 1

        return attribute, id

    def get_rvalue_and_type(self, rvalue: str, is_rvalue_building: bool, rvalue_type: str,
                            is_type_defined: bool, line: str, size: str, id: int) -> {str, bool, str, bool, int}:
        for rvalue_id in range(id, len(line)):
            if (line[rvalue_id].isalnum() or line[rvalue_id] == "_" or line[rvalue_id] == "'") and not is_type_defined:
                rvalue_type += line[rvalue_id]
            elif rvalue_type != "" and not is_type_defined:
                if line[rvalue_id] == "." and self.types_of_variables.get(rvalue_type) == "undefined":
                    rvalue_type = "char_pointer"
                elif self.types_of_variables.get(rvalue_type) is not None:
                    rvalue_type = self.types_of_variables.get(rvalue_type)
                elif "0x" in rvalue_type or rvalue_type.isdigit():
                    rvalue_type = types_sizes[size]
                elif "'" in rvalue_type:
                    rvalue_type = "char"

                if utypes.get(rvalue_type) is not None:
                    rvalue_type = utypes.get(rvalue_type)
                elif integer_types.get(rvalue_type) is not None:
                    rvalue_type = integer_types.get(rvalue_type)

                self.transfer_types.add(rvalue_type)
                is_type_defined = True

            if line[rvalue_id] in [",", ";"]:
                is_rvalue_building = False
                break

            rvalue += line[rvalue_id]

        return rvalue, is_rvalue_building, rvalue_type, is_type_defined, rvalue_id

    def get_line_without_dots(self, start_line: str, end_line: str, variable: str, variable_id: int,
                              start: str, size: str, rvalue: str, rvalue_type: str, rvalue_id: int) -> str:
        line = start_line[:variable_id + 1] + f"transfer_value_from_{rvalue_type.replace(" ", "_")}("
        if self.types_of_variables.get(variable) != "undefined":
            line += "&"
        line += f"{variable}, "
        if rvalue_type == "char_pointer":
            rvalue_start = rvalue.split("_")[2]
            line += f"{rvalue[:rvalue.find(".")].replace("= ", "").lstrip()}, {rvalue_start}, "
        else:
            line += f"{rvalue.replace("= ", "").lstrip()}, "
        line += f"{start}, {size})" + end_line[rvalue_id:]

        return line

    def get_operation(self, line: str, id: int) -> {str, bool}:
        for i in range(id, len(line)):
            operation = line[i].strip()
            if operation != "":
                return operation, True
        return "", False

    def get_correct_code(self) -> str:
        warning_in_load = False
        warning_in_store = False
        need_to_delete_brace = False
        is_rvalue_building = False
        is_operation_defined = True
        is_type_defined = False
        variable_id = 0
        id_start = 0
        rvalue = ""
        rvalue_type = ""
        start = ""
        size = ""

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
            if is_rvalue_building:
                rvalue, is_rvalue_building, rvalue_type, is_type_defined, rvalue_id =\
                    self.get_rvalue_and_type(rvalue, is_rvalue_building, rvalue_type, is_type_defined, lines[id], size,
                                             0)
                if not is_rvalue_building:
                    lines[id_start] = self.get_line_without_dots(lines[id_start], lines[id], variable, variable_id,
                                                                 start, size, rvalue, rvalue_type, rvalue_id)

                for i in range(id_start + 1, id + 1):
                    lines[i] = ""

            elif "._" in lines[id]:
                dot_id = lines[id].find("._")
                variable, variable_id = self.get_variable_and_id(lines[id], dot_id - 1)
                if self.types_of_variables.get(variable) is None:
                    continue
                start, start_id = self.get_variable_attribute_and_id(lines[id], dot_id + 2)
                size, size_id = self.get_variable_attribute_and_id(lines[id], start_id + 1)

                operation, is_operation_defined = self.get_operation(lines[id], size_id + 1)
                if not is_operation_defined:
                    continue

                if operation != "=":
                    lines[id] = lines[id][:variable_id + 1] +\
                        f"*({types_sizes.get(size)}*)((const void*)&{variable} + {start})" + lines[id][size_id + 1:]
                    continue

                rvalue, is_rvalue_building, rvalue_type, is_type_defined, rvalue_id =\
                    self.get_rvalue_and_type("", True, "", False, lines[id], size, size_id + 1)
                if not is_rvalue_building:
                    lines[id] = self.get_line_without_dots(lines[id], lines[id], variable, variable_id, start,
                                                           size, rvalue, rvalue_type, rvalue_id)
                else:
                    id_start = id

                continue

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
