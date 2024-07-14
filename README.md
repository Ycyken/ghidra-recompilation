# Ghidra recompilation
Tool to automatically post-process decompiled C code from the Ghidra framework to recompile it.

## Getting started

### Requirements
- Python 3.12+

### Installation
1. From the root directory of the repository, if you are using pip:
```
python3 -m pip install -r requirements.txt
```
2. Set the `GHIDRA_INSTALL_DIR` environment variable to point to the directory with ghidra.
### Usage
Move your binary to the root of the repository and run the script:
```
python3 postprocess.py your_file
```
When you get **your_file.c**, we recommend you compile it with -fno-stack-protectort gcc flag to disable stack protection mechanisms if you get a
segmentation fault errors when running the program.
