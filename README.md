Static analysis tool to detect the lowest cpu/fpu that will execute a dos binary, based on the binary's opcodes.

Also, it tries to determine which video modes are set via int 10h. 

Recursive search of directories and zip files is supported.

Requires radare2 on the path.


```shell

$ python -m exedet --output-format json  tests/
{"exe_path":"tests/data/trigger.com","isa":8086,"fpu":0,"video_modes":[]}
{"exe_path":"tests/data/DOOM.EXE","isa":80386,"fpu":8087,"video_modes":[]}
{"exe_path":"tests/data/mouse.exe","isa":80286,"fpu":0,"video_modes":[]}
{"exe_path":"tests/data/OXYD.EXE","isa":80286,"fpu":8087,"video_modes":[13]}
```

## Installation

Install packages with poetry:
```shell
$ poetry install
```