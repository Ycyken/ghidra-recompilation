import unittest

import pytest
import os
from src.Postprocessor import PostProcessor


class TestPostprocessor():
    binary_name = ""

    def recompile_binary(self, flags: str = "") -> int:
        postprocessor = PostProcessor(f"tests/{self.binary_name}")
        postprocessor.run()
        exit_code = os.system(f"gcc tests/{self.binary_name}.c -o tests/{self.binary_name}_recompiled -w {flags}")
        return exit_code

    @pytest.fixture
    def cleanup(self):
        yield
        try:
            os.remove(f"tests/{self.binary_name}.c")
        except OSError as e:
            pass
        try:
            os.remove(f"tests/{self.binary_name}_recompiled")
        except OSError as e:
            pass

    def test_hello_world(self, cleanup):
        self.binary_name = "hello_world"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "hello world must recompile"

    def test_bmp_viewer(self, cleanup):
        self.binary_name = "bmp_viewer"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "bmp_viewer must recompile"

    def test_bmp_viewer_O3(self, cleanup):
        self.binary_name = "bmp_viewer_O3"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "bmp_viewer with -O3 optimization flag must recompile"

    def test_linpack(self, cleanup):
        self.binary_name = "linpack"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "linpack must recompile"

    def test_calculator(self, cleanup):
        self.binary_name = "calculator"
        exit_code = self.recompile_binary()
        assert exit_code == 0, "calculator must recompile"
