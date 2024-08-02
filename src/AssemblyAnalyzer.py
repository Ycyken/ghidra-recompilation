class AssemblyAnalyzer:
    def __init__(self, addr_set, listing):
        self.code_units = listing.getCodeUnits(addr_set, False)
        self.start_address = int(str(addr_set.getMinAddress()), 16)
        self.end_address = int(str(addr_set.getMaxAddress()), 16)

    def is_function_nonuser(self):
        for code_unit in self.code_units:
            #HLT halts CPU so this instruction can't be in user functions
            if code_unit.getMnemonicString() == "HLT":
                return True

            #This part of code checks for jumps outside of functions
            #user functions can't jump out of themselves
            if code_unit.getMnemonicString() != "JMP":
                continue

            primary_reference = code_unit.getPrimaryReference(0)
            if primary_reference is None:
                continue

            destination_address = int(str(primary_reference.getToAddress()), 16)
            if self.start_address > destination_address or destination_address > self.end_address:
                return True

            return False
