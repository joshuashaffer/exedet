import tempfile
from enum import Flag, auto
from pathlib import Path
from typing import cast
from zipfile import ZipFile

import r2pipe
import typer


class InstructionSet(Flag):
    INTEL_8086 = auto()
    INTEL_80186 = auto()
    INTEL_80286 = auto()
    INTEL_80386 = auto()

    def max(self, other_cpu: 'InstructionSet') -> 'InstructionSet':
        """Return max CPU level of self and other_cpu"""
        if self == other_cpu:
            return self
        current_val = cast(int, (self | other_cpu).value)
        return InstructionSet(current_val & (current_val - 1))


class FloatingPointUnit(Flag):
    INTEGER_ONLY = auto()
    INTEL_8087 = auto()
    INTEL_80187 = auto()
    INTEL_80287 = auto()
    INTEL_80387 = auto()

    def max(self, other_cpu: 'FloatingPointUnit') -> 'FloatingPointUnit':
        """Return max FPU level of self and other_cpu"""
        if self == other_cpu:
            return self
        current_val = cast(int, (self | other_cpu).value)
        return FloatingPointUnit(current_val & (current_val - 1))


def get_isa_level(exe_path: Path) -> tuple[InstructionSet, FloatingPointUnit]:
    """
    Get the ISA level of the binary and the floating point unit
    :param exe_path:  Path to the binary
    :return: Tuple of InstructionSet and FloatingPointUnit
    """
    r2 = r2pipe.open(str(exe_path), flags=['-2'])
    r2.cmd('aaaa')
    functions = r2.cmdj('aflj')
    detected_instruction_set = InstructionSet.INTEL_8086
    detected_float_unit = FloatingPointUnit.INTEGER_ONLY
    for function in functions:
        offset = function.get('offset', -1)
        if offset == -1:
            continue
        disassembly = r2.cmdj(f'pdfj @ {offset}')
        for block in disassembly.get('ops', []):
            disassembled_instruction = block.get('disasm', '').lower()
            if 'invalid' in disassembled_instruction:
                continue
            instruction_bytes = bytes.fromhex(block.get('bytes', '90'))

            instruction_tuple = tuple(instruction_bytes)
            match instruction_tuple:
                # 386 only instructions
                case [0x0f, 0xa3, *_] | \
                     [0x0f, 0x07, *_] | \
                     [0x0f, 0x20, *_] | \
                     [0x0f, 0x21, *_] | \
                     [0x0f, 0x22, *_] | \
                     [0x0f, 0x23, *_] | \
                     [0x0f, 0x24, *_] | \
                     [0x0f, 0x26, *_] | \
                     [0x0f, 0xb3, *_] | \
                     [0x0f, 0xa4, *_] | \
                     [0x0f, 0xa5, *_] | \
                     [0x0f, 0xa0, *_] | \
                     [0x0f, 0xa1, *_] | \
                     [0x0f, 0xa8, *_] | \
                     [0x0f, 0xa9, *_] | \
                     [0x0f, 0xaf, *_] | \
                     [0x0f, 0xac, *_] | \
                     [0x0f, 0xad, *_] | \
                     [0x0f, 0xbe, *_] | \
                     [0x0f, 0xbf, *_] | \
                     [0x0f, 0x90, *_] | \
                     [0x0f, 0x91, *_] | \
                     [0x0f, 0x92, *_] | \
                     [0x0f, 0x93, *_] | \
                     [0x0f, 0x94, *_] | \
                     [0x0f, 0x95, *_] | \
                     [0x0f, 0x96, *_] | \
                     [0x0f, 0x97, *_] | \
                     [0x0f, 0x98, *_] | \
                     [0x0f, 0x99, *_] | \
                     [0x0f, 0x9a, *_] | \
                     [0x0f, 0x9b, *_] | \
                     [0x0f, 0x9c, *_] | \
                     [0x0f, 0x9d, *_] | \
                     [0x0f, 0x9e, *_] | \
                     [0x0f, 0x9f, *_] | \
                     [0x0f, 0x10, *_] | \
                     [0x0f, 0x11, *_] | \
                     [0x0f, 0x12, *_] | \
                     [0x0f, 0x13, *_] | \
                     [0x0f, 0xA6, *_] | \
                     [0x0f, 0xa7, *_] | \
                     [0xf1] | \
                     [0x0f, 0xba, *_]:
                    # 80386
                    # print(f'80386 instruction: {disassembled_instruction}')
                    detected_instruction_set = detected_instruction_set.max(InstructionSet.INTEL_80386)
                case [0xdd, 0xe0, *_] | \
                     [0xdd, 0xe8, *_] | \
                     [0xda, 0xe9, *_] | \
                     [0xd9, 0xfb, *_] | \
                     [0xd9, 0xfe, *_] | \
                     [0xd9, 0xff, *_]:
                    # 80387
                    # print(f'80387 instruction: {disassembled_instruction}')
                    detected_float_unit = detected_float_unit.max(FloatingPointUnit.INTEL_80387)

                case [0x62, *_] | \
                     [0xc8, *_] | \
                     [0xc6, *_] | \
                     [0x6d, *_] | \
                     [0xc9, *_] | \
                     [0x6e, *_] | \
                     [0x6f, *_] | \
                     [0x61, *_] | \
                     [0x60, *_] | \
                     [0x6a, *_] | \
                     [0x68, *_] | \
                     [0x6b, *_] | \
                     [0x69, *_] | \
                     [0xc0, *_] | \
                     [0xc1, *_]:
                    # 80186
                    # print(f'80186 instruction: {disassembled_instruction}')
                    detected_instruction_set = detected_instruction_set.max(InstructionSet.INTEL_80186)
                case [0xdd, 0xe4] | \
                     [0xdf, 0xe0]:
                    # 80287
                    # print(f'80287 instruction: {disassembled_instruction}')
                    detected_float_unit = detected_float_unit.max(FloatingPointUnit.INTEL_80287)
                case [0xd9, *_] | \
                     [0xdb, *_] | \
                     [0xdc, *_] | \
                     [0xdd, *_] | \
                     [0xde, *_] | \
                     [0x9b, *_] | \
                     [0xdf, *_]:
                    # 8087
                    # print(f'8087 instruction: {disassembled_instruction}')
                    detected_float_unit = detected_float_unit.max(FloatingPointUnit.INTEL_8087)
                case [0x63, *_] | \
                     [0x0f, 0x01, *_] | \
                     [0x0f, 0x06, *_] | \
                     [0x0f, 0x00, *_] | \
                     [0x0f, 0x02, *_] | \
                     [0x0f, 0x05, *_] | \
                     [0xf1, 0x0f, 0x04, *_] | \
                     [0x0f, 0x03, *_]:
                    # 80286
                    # print(f'80286 instruction: {disassembled_instruction}')
                    detected_instruction_set = detected_instruction_set.max(InstructionSet.INTEL_80286)

    return detected_instruction_set, detected_float_unit


def is_cga(exe_path: Path) -> bool:
    """
    Is the binary maybe a CGA binary?
    :param exe_path:
    :return:
    """
    video_modes = get_video_modes(exe_path)
    cga_modes_set = sum(1 for mode in video_modes if mode <= 0x07)
    # Either no video modes are set, or at least one CGA mode is set
    return len(video_modes) == 0 or cga_modes_set > 0


def get_video_modes(exe_path: Path) -> set[int]:
    """
    List the video modes that are set in the binary.
    :param exe_path:
    :return:
    """
    seen_modes = set()
    r2 = r2pipe.open(str(exe_path), flags=['-2'])
    r2.cmd('aaaa')
    functions = r2.cmdj('aflj')
    for function in functions:
        offset = function.get('offset', -1)
        if offset == -1:
            continue
        disassembly = r2.cmdj(f'pdfj @ {offset}')

        last_ah = -1
        last_al = -1
        for block in disassembly.get('ops', []):
            disassembled_instruction = block.get('disasm', '').lower()
            if 'invalid' in disassembled_instruction:
                continue
            instruction_bytes = bytes.fromhex(block.get('bytes', '90'))

            instruction_tuple = tuple(instruction_bytes)
            if instruction_tuple[0] == 0x66:
                # 16-bit instruction prefix in 32-bit mode
                instruction_tuple = instruction_tuple[1:]

            match instruction_tuple:
                case [0xCD, 0x10]:
                    # int 10h
                    if last_ah != 0:
                        continue
                    if last_al >= 0:
                        seen_modes.add(last_al)
                case [0xB4, *rest]:
                    # mov ah, imm8
                    last_ah = rest[0]
                case [0xB0, *rest]:
                    # mov al, imm8
                    last_al = rest[0]
                case [0xB8, *rest]:
                    # mov ax, imm16
                    last_ah = rest[1]
                    last_al = rest[0]
                case [0x31, 0xC0]:
                    # xor ax, ax
                    last_ah = 0
                    last_al = 0
                case [0x33, 0xC0, 0x90, 0x90]:
                    # xor eax, eax
                    last_ah = 0
                    last_al = 0
                case [0x32, 0xE4]:
                    # xor ah, ah
                    last_ah = 0
                case [0x30, 0xC0]:
                    # xor al, al
                    last_al = 0
                case [0xa0, *_]:
                    # mov al, [imm16]
                    # likely restoring the video mode
                    last_al = -1
    return seen_modes


def detect_main(file_name: Path) -> None:
    return detect(file_name)


def detect(file_name: Path,
           current_path: Path = Path(".")) -> None:
    if not file_name.exists():
        print(f'File {file_name} does not exist')
        return

    if file_name.is_dir():
        for file in file_name.iterdir():
            detect(file, current_path / file_name.name)
        return

    # if it's a zip file search it for exes and com files and run detect on them
    suffix_lower = file_name.suffix.lower()
    if suffix_lower == '.zip':
        with ZipFile(file_name) as zip_file:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_dir_path = Path(temp_dir)
                for zip_info in zip_file.infolist():
                    zip_info_filename = zip_info.filename.lower()
                    if zip_info_filename.endswith('.exe') or zip_info_filename.endswith('.com'):
                        with zip_file.open(zip_info.filename) as exe_file:
                            temp_file_path = temp_dir_path / Path(zip_info_filename).name
                            with open(temp_file_path, 'wb') as temp_file:
                                temp_file.write(exe_file.read())
                                temp_file.flush()
                                detect(temp_file_path, current_path / file_name.name)
        return

    if suffix_lower not in ['.exe', '.com']:
        return

    try:
        detected_instruction_set, detected_float_unit = get_isa_level(file_name)
        video_modes = get_video_modes(file_name)
    except BrokenPipeError:
        # This happens when r2pipe is not able to open the file
        return
    print(
        f'{current_path / file_name.name};{detected_instruction_set};{detected_float_unit};{",".join(map(str, video_modes))}')


if __name__ == '__main__':
    typer.run(detect_main)
