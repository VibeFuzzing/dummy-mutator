# dummy-mutator

Part of the VibeFuzzer project, a senior design project.

## Developing with VS Code and other `clangd`-compatible programs

This project uses a plain Makefile. Unfortunately, `clangd` can't read Makefile.

The simplest way to create a file that `clangd` can read is to install `bear` from your local package repository and run `bear -- make`. This will generate a `compile_commands.json` file that has all the information `clangd` needs. This file would just be committed to the repository, but it requires an absolute path.

## Building

This program is very simple; just run `make`. This will check out the `AFLplusplus` repository for includes if it has't been already, then compile the single C file into a library that AFL++ can load.

## Usage with AFL

Add `AFL_CUSTOM_MUTATOR_LIBRARY="/path/to/libdummymutator.so"` to the beginning of the AFL command line.

Here's a full command the dev used testing this program:

```sh
AFL_TMPDIR=/tmp AFL_PRELOAD=./libdesock.so AFL_CUSTOM_MUTATOR_LIBRARY=$(realpath ./libdummymutator.so) afl-fuzz -i corpus -o findings -m none -- ./vulnerable-server-afl
```
