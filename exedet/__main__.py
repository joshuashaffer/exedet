import logging
import sys
import tempfile
from enum import Enum, Flag, auto
from pathlib import Path
from typing import Annotated, Optional, TextIO
from zipfile import ZipFile

import r2pipe
import typer
from pydantic import BaseModel


class OutputFormat(str, Enum):
    CSV = 'csv'
    JSON = 'json'


class InstructionSet(Flag):
    """Instruction set architecture level"""

    INTEL_8086 = auto()
    INTEL_80186 = auto()
    INTEL_80286 = auto()
    INTEL_80386 = auto()

    def max(self, other_cpu: 'InstructionSet') -> 'InstructionSet':
        """Return max CPU level of self and other_cpu"""
        if self == other_cpu:
            return self
        current_val = (self | other_cpu).value
        return InstructionSet(current_val & (current_val - 1))

    def processor_as_int(self) -> int:
        match self:
            case InstructionSet.INTEL_8086:
                return 8086
            case InstructionSet.INTEL_80186:
                return 80186
            case InstructionSet.INTEL_80286:
                return 80286
            case InstructionSet.INTEL_80386:
                return 80386
            case _:
                raise ValueError(f'Unknown ISA: {self}')


class FloatingPointUnit(Flag):
    """Floating point unit level"""

    INTEGER_ONLY = auto()
    INTEL_8087 = auto()
    INTEL_80187 = auto()
    INTEL_80287 = auto()
    INTEL_80387 = auto()

    def max(self, other_cpu: 'FloatingPointUnit') -> 'FloatingPointUnit':
        """Return max FPU level of self and other_cpu"""
        if self == other_cpu:
            return self
        current_val = (self | other_cpu).value
        return FloatingPointUnit(current_val & (current_val - 1))

    def processor_as_int(self) -> int:
        """Return the processor as an integer"""
        match self:
            case FloatingPointUnit.INTEGER_ONLY:
                return 0
            case FloatingPointUnit.INTEL_8087:
                return 8087
            case FloatingPointUnit.INTEL_80187:
                return 80187
            case FloatingPointUnit.INTEL_80287:
                return 80287
            case FloatingPointUnit.INTEL_80387:
                return 80387
            case _:
                raise ValueError(f'Unknown FPU: {self}')


class OutputModel(BaseModel):
    """Output model for the json output"""

    exe_path: Path
    isa: int
    fpu: int
    video_modes: set[int]

    class Config:
        """Pydantic config"""

        extra = 'forbid'
        frozen = True
        validate_assignment = True


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
    # fmt: off
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
                case [0x0f, 0x07, *_] | \
                     [0x0f, 0x10, *_] | \
                     [0x0f, 0x11, *_] | \
                     [0x0f, 0x12, *_] | \
                     [0x0f, 0x13, *_] | \
                     [0x0f, 0x20, *_] | \
                     [0x0f, 0x21, *_] | \
                     [0x0f, 0x22, *_] | \
                     [0x0f, 0x23, *_] | \
                     [0x0f, 0x24, *_] | \
                     [0x0f, 0x26, *_] | \
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
                     [0x0f, 0xa0, *_] | \
                     [0x0f, 0xa1, *_] | \
                     [0x0f, 0xa3, *_] | \
                     [0x0f, 0xa4, *_] | \
                     [0x0f, 0xa5, *_] | \
                     [0x0f, 0xA6, *_] | \
                     [0x0f, 0xa7, *_] | \
                     [0x0f, 0xa8, *_] | \
                     [0x0f, 0xa9, *_] | \
                     [0x0f, 0xac, *_] | \
                     [0x0f, 0xad, *_] | \
                     [0x0f, 0xaf, *_] | \
                     [0x0f, 0xb3, *_] | \
                     [0x0f, 0xba, *_] | \
                     [0x0f, 0xbe, *_] | \
                     [0x0f, 0xbf, *_] | \
                     [0xf1]:
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

                case [0x60, *_] | \
                     [0x61, *_] | \
                     [0x62, *_] | \
                     [0x68, *_] | \
                     [0x69, *_] | \
                     [0x6a, *_] | \
                     [0x6b, *_] | \
                     [0x6d, *_] | \
                     [0x6e, *_] | \
                     [0x6f, *_] | \
                     [0xc0, *_] | \
                     [0xc1, *_] | \
                     [0xc6, *_] | \
                     [0xc8, *_] | \
                     [0xc9, *_]:
                    # 80186
                    # print(f'80186 instruction: {disassembled_instruction}')
                    detected_instruction_set = detected_instruction_set.max(InstructionSet.INTEL_80186)
                    
                case [0xdd, 0xe4] | \
                     [0xdf, 0xe0]:
                    # print(f'80287 instruction: {disassembled_instruction}')
                    detected_float_unit = detected_float_unit.max(FloatingPointUnit.INTEL_80287)
                    
                case [0x9b, *_] | \
                     [0xd8, *_] | \
                     [0xd9, *_] | \
                     [0xdb, *_] | \
                     [0xdc, *_] | \
                     [0xdd, *_] | \
                     [0xde, *_] | \
                     [0xdf, *_]:
                    # print(f'8087 instruction: {disassembled_instruction}')
                    detected_float_unit = detected_float_unit.max(FloatingPointUnit.INTEL_8087)
                    
                case [0x0f, 0x00, *_] | \
                     [0x0f, 0x01, *_] | \
                     [0x0f, 0x02, *_] | \
                     [0x0f, 0x03, *_] | \
                     [0x0f, 0x05, *_] | \
                     [0x0f, 0x06, *_] | \
                     [0x63, *_] | \
                     [0xf1, 0x0f, 0x04, *_]:
                    # 80286
                    # print(f'80286 instruction: {disassembled_instruction}')
                    detected_instruction_set = detected_instruction_set.max(InstructionSet.INTEL_80286)
                    
                case [0x00, *_] | \
                     [0x01, *_] | \
                     [0x02, *_] | \
                     [0x03, *_] | \
                     [0x04, *_] | \
                     [0x05, *_] | \
                     [0x06, *_] | \
                     [0x07, *_] | \
                     [0x0E, *_] | \
                     [0x0F, *_] | \
                     [0x10, *_] | \
                     [0x11, *_] | \
                     [0x12, *_] | \
                     [0x13, *_] | \
                     [0x15, *_] | \
                     [0x17, *_] | \
                     [0x18, *_] | \
                     [0x19, *_] | \
                     [0x1A, *_] | \
                     [0x1B, *_] | \
                     [0x1C, *_] | \
                     [0x1D, *_] | \
                     [0x1E, *_] | \
                     [0x1F, *_] | \
                     [0x20, *_] | \
                     [0x21, *_] | \
                     [0x22, *_] | \
                     [0x23, *_] | \
                     [0x24, *_] | \
                     [0x25, *_] | \
                     [0x28, *_] | \
                     [0x29, *_] | \
                     [0x2A, *_] | \
                     [0x2B, *_] | \
                     [0x2C, *_] | \
                     [0x2D, *_] | \
                     [0x30, *_] | \
                     [0x31, *_] | \
                     [0x32, *_] | \
                     [0x33, *_] | \
                     [0x34, *_] | \
                     [0x35, *_] | \
                     [0x37, *_] | \
                     [0x38, *_] | \
                     [0x39, *_] | \
                     [0x3A, *_] | \
                     [0x3B, *_] | \
                     [0x3C, *_] | \
                     [0x3D, *_] | \
                     [0x40, *_] | \
                     [0x41, *_] | \
                     [0x42, *_] | \
                     [0x43, *_] | \
                     [0x44, *_] | \
                     [0x45, *_] | \
                     [0x46, *_] | \
                     [0x47, *_] | \
                     [0x48, *_] | \
                     [0x49, *_] | \
                     [0x4A, *_] | \
                     [0x4B, *_] | \
                     [0x4C, *_] | \
                     [0x4D, *_] | \
                     [0x4E, *_] | \
                     [0x4F, *_] | \
                     [0x50, *_] | \
                     [0x51, *_] | \
                     [0x52, *_] | \
                     [0x53, *_] | \
                     [0x54, *_] | \
                     [0x55, *_] | \
                     [0x56, *_] | \
                     [0x57, *_] | \
                     [0x58, *_] | \
                     [0x59, *_] | \
                     [0x5A, *_] | \
                     [0x5B, *_] | \
                     [0x5C, *_] | \
                     [0x5D, *_] | \
                     [0x5E, *_] | \
                     [0x5F, *_] | \
                     [0x70, *_] | \
                     [0x71, *_] | \
                     [0x72, *_] | \
                     [0x73, *_] | \
                     [0x74, *_] | \
                     [0x75, *_] | \
                     [0x76, *_] | \
                     [0x77, *_] | \
                     [0x78, *_] | \
                     [0x79, *_] | \
                     [0x7A, *_] | \
                     [0x7B, *_] | \
                     [0x7C, *_] | \
                     [0x7D, *_] | \
                     [0x7E, *_] | \
                     [0x7F, *_] | \
                     [0x80, *_] | \
                     [0x81, *_] | \
                     [0x84, *_] | \
                     [0x85, *_] | \
                     [0x86, *_] | \
                     [0x87, *_] | \
                     [0x8C, *_] | \
                     [0x8D, *_] | \
                     [0x8E, *_] | \
                     [0x90] | \
                     [0x91, *_] | \
                     [0x92, *_] | \
                     [0x93, *_] | \
                     [0x94, *_] | \
                     [0x95, *_] | \
                     [0x96, *_] | \
                     [0x97, *_] | \
                     [0x98, *_] | \
                     [0x99, *_] | \
                     [0x9A, 0xe8, 0xff, *_] | \
                     [0x9C, *_] | \
                     [0x9F, *_] | \
                     [0x9A, *_] | \
                     [0xA0, *_] | \
                     [0xA1, *_] | \
                     [0xA2, *_] | \
                     [0xA3, *_] | \
                     [0xA4, *_] | \
                     [0xA5, *_] | \
                     [0xA6, *_] | \
                     [0xA7, *_] | \
                     [0xA8, *_] | \
                     [0xA9, *_] | \
                     [0xAC, *_] | \
                     [0xAD, *_] | \
                     [0xAE, *_] | \
                     [0xAF, *_] | \
                     [0xC0, *_] | \
                     [0xC1, *_] | \
                     [0xC2, *_] | \
                     [0xC3, *_] | \
                     [0xC4, *_] | \
                     [0xC5, *_] | \
                     [0xC9, *_] | \
                     [0xCA, *_] | \
                     [0xCB, *_] | \
                     [0xCD, *_] | \
                     [0xD0, *_] | \
                     [0xD1, *_] | \
                     [0xD2, *_] | \
                     [0xD3, *_] | \
                     [0xD5, *_] | \
                     [0xD7, *_] | \
                     [0xE0, *_] | \
                     [0xE1, *_] | \
                     [0xE2, *_] | \
                     [0xE3, *_] | \
                     [0xE4, *_] | \
                     [0xE5, *_] | \
                     [0xE6, *_] | \
                     [0xE7, *_] | \
                     [0xE8, *_] | \
                     [0xE9, *_] | \
                     [0xEA, *_] | \
                     [0xEB, *_] | \
                     [0xEC, *_] | \
                     [0xED, *_] | \
                     [0xEE, *_] | \
                     [0xEF, *_] | \
                     [0xF0, *_] | \
                     [0xF2, *_] | \
                     [0xF3, *_] | \
                     [0xF6, *_] | \
                     [0xF7, *_] | \
                     [0xF8, *_] | \
                     [0xF9, *_] | \
                     [0xFB, *_] | \
                     [0xFD, *_] | \
                     [0xFE, *_] | \
                     [0xFF, *_]:
                    # 8086, So that unknown instructions are handled by the default case
                    ...

                case _:
                    # Unknown instruction
                    # print(f'Unknown instruction: {disassembled_instruction}  {instruction_bytes.hex()}')
                    ...
    # fmt: on
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
                    logging.debug(
                        f'Found int 10h with AH={last_ah} and AL={last_al} at function at 0x{offset:X}'
                    )
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
                case [0xA0, *_]:
                    # mov al, [imm16]
                    # likely restoring the video mode
                    last_al = -1
    return seen_modes


def detect_main(
    file_name: Annotated[Path, typer.Argument(dir_okay=True, exists=True)],
    output_format: OutputFormat = typer.Option(
        OutputFormat.CSV, case_sensitive=False
    ),
    output_file: Optional[Path] = None,
) -> None:
    """Detect the instruction set, floating point unit and video modes of a DOS binary."""
    output_fd: TextIO
    if output_file is not None:
        output_fd = open(output_file, 'w')
    else:
        output_fd = sys.stdout

    detect(file_name, output_format=output_format, output_fd=output_fd)

    if output_fd is not sys.stdout:
        output_fd.close()


def detect(
    file_name: Path,
    *,
    output_format: OutputFormat,
    output_fd: TextIO,
    current_path: Path = Path('.'),
) -> None:
    if not file_name.exists():
        print(f'File {file_name} does not exist')
        return

    if file_name.is_dir():
        for file in file_name.iterdir():
            detect(
                file,
                output_format=output_format,
                output_fd=output_fd,
                current_path=current_path / file_name.name,
            )
        return

    # if it's a zip file search it for exes and com files and run detect on them
    suffix_lower = file_name.suffix.lower()
    if suffix_lower == '.zip':
        with ZipFile(file_name) as zip_file:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_dir_path = Path(temp_dir)
                for zip_info in zip_file.infolist():
                    zip_info_filename = zip_info.filename.lower()
                    if zip_info_filename.endswith(
                        '.exe'
                    ) or zip_info_filename.endswith('.com'):
                        with zip_file.open(zip_info.filename) as exe_file:
                            temp_file_path = (
                                temp_dir_path / Path(zip_info_filename).name
                            )
                            with open(temp_file_path, 'wb') as temp_file:
                                temp_file.write(exe_file.read())
                                temp_file.flush()
                                detect(
                                    temp_file_path,
                                    output_format=output_format,
                                    output_fd=output_fd,
                                    current_path=current_path / file_name.name,
                                )
        return

    if suffix_lower not in ['.exe', '.com']:
        return

    try:
        detected_instruction_set, detected_float_unit = get_isa_level(
            file_name
        )
        video_modes = get_video_modes(file_name)
    except BrokenPipeError:
        # This happens when r2pipe is not able to open the file
        return

    output_data = OutputModel(
        exe_path=current_path / file_name.name,
        isa=detected_instruction_set.processor_as_int(),
        fpu=detected_float_unit.processor_as_int(),
        video_modes=video_modes,
    )

    match output_format:
        case OutputFormat.CSV:
            output_fd.write(
                f'{output_data.exe_path};{output_data.isa};{output_data.fpu};{",".join(map(str, output_data.video_modes))}'
            )
        case OutputFormat.JSON:
            output_fd.write(output_data.model_dump_json())
    output_fd.write('\n')
    output_fd.flush()


if __name__ == '__main__':
    typer.run(detect_main)
