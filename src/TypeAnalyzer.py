import logging

logger = logging.getLogger(__name__)

floating_point_instructions = ["MOVSS", "MOVSD", "ADDSS", "ADDSD", "SUBSS", "SUBSD", "MULSS", "MULSD",
                               "DIVSS", "DIVSD", "MINSS", "MINSD", "MAXSS", "MAXSD", "SQRTSS", "SQRTSD",
                               "RCPSS", "RCPSD", "RSQRTSS", "RSQRTSD", "CMPSS", "CMPSD", "CMPEQSS", "CMPEQSD",
                               "CMPLTSS", "CMPLTSD", "CMPLESS", "CMPLESD", "CMPNESS", "CMPNESD", "CMPUNORDSS",
                               "CMPUNORDSD", "CMPNLTSS", "CMPNLTSD", "CMPNLESS", "CMPNLESD", "CMPORDSS", "CMPORDSD"]

float_types = {
    "undefined4": "float",
    "undefined8": "double",
    "undefined": "double"
}

utypes = {
    "byte": "unsigned char",
    "ulong": "unsigned long",
    "ulonglong": "unsigned long long",
    "uint": "unsigned int",
    "ushort": "unsigned short"
}

integer_types = {
    "undefined1": "char",
    "undefined2": "short",
    "undefined3": "int",
    "undefined4": "int",
    "undefined5": "long long",
    "undefined6": "long long",
    "undefined7": "long long",
    "undefined8": "long long",
    "undefined": "char",
}


class TypeAnalyzer:
    def __init__(self, flat_api):
        self.flat_api = flat_api
        self.program = flat_api.getCurrentProgram()
        self.listing = self.program.getListing()

    def get_symbol_type_and_value(self, symbol) -> (str, str):
        """
        Find the data corresponding to this symbol and return its type and value.
        :param symbol:
        :return: (type, value) or None if there is no data for this symbol
        """
        addr = symbol.getAddress()
        data = self.listing.getDataAt(addr)
        if data is None:
            return None
        data_type = data.getDataType().getDisplayName()
        value = data.getValue()

        data_type_default = data.getDataType().getName()
        if (data_type != data_type_default):
            logger.warning(
                f"Datatype name and displayName are different: {data_type_default} and {data_type}")

        if self.is_symbol_float(symbol):
            data_type = float_types.get(data_type, data_type)
            if value is None:
                value = "0"
            elif data_type == "float":
                value = self.flat_api.getFloat(addr)
            else:
                value = self.flat_api.getDouble(addr)
        elif data_type == "pointer":
            data_type = "void *"
            if value is None:
                value = "NULL"
            elif not isinstance(value, str):
                value = int(str(value), 16)
        elif data_type == "string":
            data_type = "char *"
            if value is None:
                value = "NULL"
            elif isinstance(value, str):
                value = '\"' + value + '\"'
            else:
                value = int(str(value), 16)
        elif "char *" in data_type or "char[" in data_type:
            if value is None:
                value = "NULL"
            elif isinstance(value, str):
                value = '\"' + value + '\"'
            else:
                value = int(str(value), 16)
        elif "bool" in data_type.lower():
            data_type = "bool"
            if value is None:
                value = "false"
        else:
            data_type = integer_types.get(data_type, data_type)
            data_type = utypes.get(data_type, data_type)
            if not isinstance(value, str) and value is not None:
                value = int(str(value), 16)
            elif data_type == "char" and isinstance(value, str):
                value = "\'" + value + "\'"
        if value is None:
            return data_type, value
        return data_type, str(value).lower()

    def correct_array_type_declaration(self, data_type: str, var_name: str) -> (str, str):
        if "[" not in data_type or "]" not in data_type:
            return data_type, var_name
        opening_sq_bracket_index = data_type.index("[")
        closing_sq_bracket_index = data_type.index("]")
        if closing_sq_bracket_index == (opening_sq_bracket_index + 1):
            logger.warning(f"Array data type without size is met: {data_type}")
            return data_type, var_name

        array_size = data_type[opening_sq_bracket_index:closing_sq_bracket_index + 1]
        data_type = data_type[:opening_sq_bracket_index]
        var_name = var_name + array_size
        return data_type, var_name

    def is_symbol_float(self, symbol) -> bool:
        addr = symbol.getAddress()
        data = self.listing.getDataAt(addr)
        if data is None:
            return False
        type = data.getDataType().getName()
        if "float" in type or "double" in type.lower():
            return True
        if not ("undefined" in type.lower()):
            return False

        for reference in symbol.getReferences():
            addr = reference.getFromAddress()
            code_unit = self.listing.getCodeUnitContaining(addr)
            if code_unit is None:
                continue
            mnemonic = code_unit.getMnemonicString()
            if mnemonic in floating_point_instructions:
                return True
        return False
