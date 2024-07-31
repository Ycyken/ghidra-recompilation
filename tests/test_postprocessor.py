import pytest
import os
from src.Postprocessor import PostProcessor

binaries_path = "tests/binaries"


class TestPostprocessor():
    binary_name = ""

    def recompile_binary(self, flags: str = "") -> int:
        self.decompile_binary()
        exit_code = os.system(
            f"gcc {binaries_path}/{self.binary_name}.c -o {binaries_path}/{self.binary_name}_recompiled -w {flags}")
        return exit_code

    def decompile_binary(self, flags: str = ""):
        postprocessor = PostProcessor(f"{binaries_path}/{self.binary_name}")
        postprocessor.run()

    def run_binary(self, options: str = "") -> str:
        pipe = os.popen(f"{binaries_path}/{self.binary_name}_recompiled {options}", "r")
        output = pipe.read()
        assert pipe.close() is None, "recompiled program must exit successfully"
        return output

    @pytest.fixture
    def cleanup(self):
        yield
        try:
            os.remove(f"{binaries_path}/{self.binary_name}.c")
        except OSError:
            pass
        try:
            os.remove(f"{binaries_path}/{self.binary_name}_recompiled")
        except OSError:
            pass

    def test_hello_world(self, cleanup):
        self.binary_name = "hello_world"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "hello world must recompile"

        output = self.run_binary()
        assert output == "Hello world!\n"

    def test_bmp_viewer(self, cleanup):
        self.binary_name = "bmp_viewer"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "bmp_viewer must recompile"

    def test_bmp_viewer_O3(self, cleanup):
        self.binary_name = "bmp_viewer_O3"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "bmp_viewer with -O3 optimization flag must recompile"

    def test_bmp_viewer_stripped(self, cleanup):
        self.binary_name = "bmp_viewer_stripped"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "stripped bmp_viewer must recompile"

    def test_linpack(self, cleanup):
        self.binary_name = "linpack"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "linpack must recompile"

        output = self.run_binary().split("\n")
        assert output[3] == "LINPACK benchmark, Double precision.", "linpack must give correct output"

    def test_linpack_stripped(self, cleanup):
        self.binary_name = "linpack_stripped"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "stripped linpack must recompile"

        output = self.run_binary().split("\n")
        assert output[3] == "LINPACK benchmark, Double precision.", "linpack must give correct output"

    def test_calculator(self, cleanup):
        self.binary_name = "calculator"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "calculator must recompile"

    def test_smoke_integral_sinx(self, cleanup):
        self.binary_name = "integral_sinx"
        self.decompile_binary("--revpol")

    def test_smoke_ls(self, cleanup):
        self.binary_name = "ls"
        self.decompile_binary()

    def test_smoke_pwd(self, cleanup):
        self.binary_name = "pwd"
        self.decompile_binary()

    def test_smoke_cat(self, cleanup):
        self.binary_name = "cat"
        self.decompile_binary()

    def test_smoke_yes(self, cleanup):
        self.binary_name = "yes"
        self.decompile_binary()
