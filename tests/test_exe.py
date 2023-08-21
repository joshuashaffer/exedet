from pathlib import Path

import r2pipe

test_data = Path(__file__).parent / 'data'


# Instructions that are not available on 8086/8088:
unsupported_instructions = [
    'enter',
    'leave',
    'popa',
    'pusha',
    'lgdt',
    'lidt',
    'lmsw',
    'clts',
    'sgdt',
    'sidt',
    'str',
    'loadall',
    'storeall',
    'lodsd',
    'stosd',
    'cmpsd',
    'scasd',
    'insd',
    'outsd',
    'iretd',
    'jecxz',
    'pushad',
    'popad',
    'bswap',
    'cmpxchg8b',
    'cpuid',
]

unsupported_registeres = [
    'esp',
    'ebp',
    'eip',
    'eflags',
    'fs',
    'gs',
    'cr0',
    'cr1',
    'cr2',
    'cr3',
    'cr4',
    'cr5',
    'cr6',
    'cr7',
    'rax',
    'rbx',
    'rcx',
    'rdx',
    'rsi',
    'rdi',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
    'xmm0',
    'xmm1',
    'xmm2',
    'xmm3',
    'xmm4',
    'xmm5',
    'xmm6',
    'xmm7',
    'xmm8',
    'xmm9',
    'xmm10',
    'xmm11',
    'xmm12',
    'xmm13',
    'xmm14',
    'xmm15',
]


def test_r2pipe_exe():
    r2 = r2pipe.open(str(test_data / 'OXYD.EXE'))
    r2.cmd('aaaa')

    exe_info = r2.cmdj('ij')
    assert type(exe_info) == dict

    bin = exe_info.get('bin', {})
    assert bin.get('arch', '') == 'x86'
    assert bin.get('bits', 0) == 16
    assert bin.get('os', '') == 'DOS'

    functions = r2.cmdj('aflj')

    for function in functions:
        offset = function.get('offset', -1)
        if offset == -1:
            continue
        # print(f'Function: {offset}')
        disassembly = r2.cmdj(f'pdfj @ {offset}')
        # print(f'Disassembly: {disassembly}')
        for block in disassembly.get('ops', []):
            disasm = block.get('disasm', '')
            if 'invalid' in disasm:
                continue
            opcode, *args = disasm.split()
            assert opcode not in unsupported_instructions

            # check that only supported registers are used
            for arg in args:
                if arg in unsupported_registeres:
                    print(f'Unsupported register: {arg}')
                    print(f'Function: {offset}')
                    print(f'Disassembly: {disassembly}')
                    assert False
        print('-' * 80)


def test_iset():
    from exedet.__main__ import (
        get_isa_level,
        InstructionSet,
        FloatingPointUnit,
    )

    ret = get_isa_level(test_data / 'OXYD.EXE')
    assert ret[0] == InstructionSet.INTEL_80286
    assert ret[1] == FloatingPointUnit.INTEL_8087


def test_isa_386():
    from exedet.__main__ import (
        get_isa_level,
        InstructionSet,
        FloatingPointUnit,
    )

    ret = get_isa_level(test_data / 'DOOM.EXE')
    assert ret[0] == InstructionSet.INTEL_80386
    assert ret[1] == FloatingPointUnit.INTEL_8087


def test_doom_graphic():
    from exedet.__main__ import get_video_modes

    ret = get_video_modes(test_data / 'DOOM.EXE')
    print(ret)


def test_cga_det():
    from exedet.__main__ import is_cga

    assert not is_cga(test_data / 'OXYD.EXE')


def test_not_set():
    from exedet.__main__ import is_cga

    assert is_cga(test_data / 'mouse.exe')


def test_get_video_modes():
    from exedet.__main__ import get_video_modes

    modes = get_video_modes(test_data / 'OXYD.EXE')
    print(modes)


def test_get_video_modes_2():
    from exedet.__main__ import get_video_modes

    modes = get_video_modes(test_data / 'mouse.exe')
    print(modes)
