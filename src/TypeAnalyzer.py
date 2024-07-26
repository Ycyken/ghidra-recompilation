import logging

logger = logging.getLogger(__name__)

floating_point_instructions = ["MOVSS", "MOVSD", "ADDSS", "ADDSD", "SUBSS", "SUBSD", "MULSS", "MULSD",
                               "DIVSS", "DIVSD", "MINSS", "MINSD", "MAXSS", "MAXSD", "SQRTSS", "SQRTSD",
                               "RCPSS", "RCPSD", "RSQRTSS", "RSQRTSD", "CMPSS", "CMPSD", "CMPEQSS", "CMPEQSD",
                               "CMPLTSS", "CMPLTSD", "CMPLESS", "CMPLESD", "CMPNESS", "CMPNESD", "CMPUNORDSS",
                               "CMPUNORDSD", "CMPNLTSS", "CMPNLTSD", "CMPNLESS", "CMPNLESD", "CMPORDSS", "CMPORDSD"]

float_types = {
    "undefined4": "double",
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
        display_type = data.getDataType().getDisplayName()
        value = data.getValue()

        data_type_default = data.getDataType().getName()
        if (display_type != data_type_default):
            logger.warning(
                f"Datatype name and displayName are different: {data_type_default} and {display_type}")

        if self.is_symbol_float(symbol):
            display_type = float_types.get(display_type, display_type)
            if value is None:
                value = "0"
            elif display_type == "float":
                value = self.flat_api.getFloat(addr)
            else:
                value = self.flat_api.getDouble(addr)
        elif display_type == "pointer":
            display_type = "void *"
            if value is None:
                value = "NULL"
            else:
                value = int(str(value), 16)
        elif display_type == "string":
            display_type = "char *"
            if value is None:
                value = "NULL"
            elif type(value) is str:
                value = '\"' + value + '\"'
            else:
                value = int(str(value), 16)
        elif "char *" in display_type or "char[" in display_type:
            if type(value) is str:
                value = '\"' + value + '\"'
            else:
                value = int(str(value), 16)
        elif "bool" in display_type.lower():
            display_type = "bool"
            if value is None:
                value = "false"
        else:
            display_type = integer_types.get(display_type, display_type)
            display_type = utypes.get(display_type, display_type)
            if value is None:
                value = "0"
            else:
                value = int(str(value), 16)
        return display_type, str(value).lower()

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
