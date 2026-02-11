# :mirror: Memory Mirror

## What is this?
This tool allows you to dump a process's memory regions for reverse engineering purposes.

## Why
 - Sometimes programs use obfuscation products that decrypts parts of the binary during runtime. This tool allows you to nab a copy of the executable where that process has been applied making the otherwise encrypted code readable.
 - Sometimes it's convenient to have a copy of the runtime heap memory inside of ghidra. Doing this allows you to immediately view the data targeted by some routine without needing to have a running instance of the program under a debugger.

## How do I use this?

The latest usage instructions can always be retrieved by invoking:
```shell
memory-mirror.exe help
```

Example output:
```
Usage: memory-mirror.exe <COMMAND>

Commands:
  list          List any running processes that are available for dumping
  list-modules  List the modules of the provided process
  list-regions  List the memory regions of the provided process
  dump-regions  Dump a given process's memory regions to disk
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

To then find out more about a specific command you can invoke `help <command>:
```shell
memory-mirror.exe help dump-regions
```

Example output:
```
Dump a given process's memory regions to disk

Usage: memory-mirror.exe dump-regions [OPTIONS] --pid <PID> --output-dir <OUTPUT_DIR>

Options:
  -p, --pid <PID>                Process ID of the process to dump
  -o, --output-dir <OUTPUT_DIR>  Directory to write the output to
  -s, --suspend-threads          Suspend all the threads before dumping
  -f, --fixup-pe-headers         Correct the PE headers SizeOfRawData and PointerToRawData to point to the aligned start of the raw data. This makes it possible for Ghidra to find the entrypoint
  -h, --help                     Print help
  -V, --version                  Print version
```
