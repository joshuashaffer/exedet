Static analysis tool to detect the lowest cpu/fpu that will execute a dos binary, based on the binary's opcodes.

Also, it tries to determine which video modes are set via int 10h. 

Requires radare2 on the path.


```shell

$ python -m exedet.detect_8088 tests
tests/data/trigger.com;InstructionSet.INTEL_8086;FloatingPointUnit.INTEGER_ONLY;
tests/data/DOOM.EXE;InstructionSet.INTEL_80386;FloatingPointUnit.INTEL_8087;
tests/data/mouse.exe;InstructionSet.INTEL_80286;FloatingPointUnit.INTEGER_ONLY;
tests/data/OXYD.EXE;InstructionSet.INTEL_80286;FloatingPointUnit.INTEL_8087;13

```