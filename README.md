# Ghidra recompilation

Tool to make [Ghidra](https://github.com/NationalSecurityAgency/ghidra) decompiled C code recompilable and easy to read.
It automatically post-processes the decompiled
code and also analyses the binary file so that you can recompile it.

## Getting started

### Requirements

- Python 3.12+
- Ghidra 11.1.2+

### Creating venv

```bash
python3 -m venv .venvname
source .venvname/bin/activate
```
### Installation

1. From the root directory of the repository, if you are using pip:

```bash
python3 -m pip install -r requirements.txt
```

2. Set the `GHIDRA_INSTALL_DIR` environment variable to point to the directory with ghidra.

### Usage

Move your binary to the root of the repository and run the script:

```bash
python3 postprocess.py your_file
```

## Development

### Requirements

```bash
python3 -m pip install -r requirements-dev.txt
```

### Pre-commit

#### Install pre-commit-hooks

```bash
pre-commit install
```

### Run tests
```bash
pytest tests -v
```
