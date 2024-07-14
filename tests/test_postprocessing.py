import unittest
import shutil
import os
from src.Postprocessor import PostProcessor


class TestPostprocessor(unittest.TestCase):
    filename = ""
    exit_code = 0

    def setUp(self):
        self.filename = ""
        self.exit_code = 0

    def tearDown(self):
        try:
            os.remove(f"tests/{self.filename}.c")
        except OSError as e:
            print(e)
        try:
            os.remove(f"tests/{self.filename}_recompiled")
        except OSError as e:
            print(e)
        try:
            shutil.rmtree(f"tests/{self.filename}_ghidra")
        except OSError as e:
            print(e)

    def compile_postprocessed_file(self, flags=""):
        self.exit_code = os.system(f"gcc tests/{self.filename}.c -o tests/{self.filename}_recompiled -w -M {flags}")

    def test_hello_world(self):
        self.filename = "hello_world"
        self.postprocessor = PostProcessor("tests/" + self.filename)
        self.postprocessor.run()

        self.compile_postprocessed_file()
        self.assertEqual(self.exit_code, 0, "Hello world must recompile")

    def test_bmp_viewer(self):
        self.filename = "bmp_viewer"
        self.postprocessor = PostProcessor("tests/" + self.filename)
        self.postprocessor.run()

        self.compile_postprocessed_file("-fno-stack-protector")
        self.assertEqual(self.exit_code, 0, "bmp_viewer must recompile")


if __name__ == "__main__":
    unittest.main()
