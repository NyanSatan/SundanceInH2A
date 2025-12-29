# YOLO code signature fixing algorithm for Mach-Os & dyld shared cache,
# only 32-bit binaries with adhoc signature are assumed

import os
import hashlib
from ctypes import *
from pathlib import Path
from typing import List, Tuple

class YolosignError(Exception):
    pass

PAGE_SIZE = 0x1000

MH_MAGIC = 0xfeedface

class MachOHeader(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("cputype", c_uint32),
        ("cpusubtype", c_uint32),
        ("filetype", c_uint32),
        ("ncmds", c_uint32),
        ("sizeofcmds", c_uint32),
        ("flags", c_uint32)
    ]

    @classmethod
    def load(cls, data: bytes) -> "MachOHeader":
        c = cls.from_buffer_copy(data[:sizeof(MachOHeader)])
        if c.magic != MH_MAGIC:
            raise YolosignError("bad magic in Mach-O")

        return c

LC_SEGMENT	= 0x1
LC_CODE_SIGNATURE = 0x1d

class LoadCommand(Structure):
    _fields_ = [
        ("cmd", c_uint32),
        ("cmdsize", c_uint32)
    ]

class SegmentCommand(Structure):
    _fields_ = [
        ("cmd", c_uint32),
        ("cmdsize", c_uint32),
        ("segname", ARRAY(c_char, 16)),
        ("vmaddr", c_uint32),
        ("vmsize", c_uint32),
        ("fileoff", c_uint32),
        ("filesize", c_uint32),
        ("maxprot", c_uint32),
        ("initprot", c_uint32),
        ("nsects", c_uint32),
        ("flags", c_uint32)
    ]

class LinkeditDataCommand(Structure):
    _fields_ = [
        ("cmd", c_uint32),
        ("cmdsize", c_uint32),
        ("dataoff", c_uint32),
        ("datasize", c_uint32)
    ]

class MachO:
    def __init__(self, fd):
        self.fd = fd

        self.fd.seek(0)
        self.header = MachOHeader.load(
            self.fd.read(sizeof(MachOHeader)))

        self.fd.seek(sizeof(MachOHeader))
        self.cmds = self.fd.read(self.header.sizeofcmds)

    def find_cmd(self, cmdtype: int, prev_idx: int = 0) -> Tuple[int, bytes]:
        off = 0
        for i in range(self.header.ncmds):
            cmd = LoadCommand.from_buffer_copy(self.cmds, off)
            if prev_idx < i:
                if cmd.cmd == cmdtype:
                    self.fd.seek(sizeof(MachOHeader) + off)
                    return i, self.fd.read(cmd.cmdsize)

            off += cmd.cmdsize

        raise StopIteration()

    def find_segment(self, name: str) -> bytes:
        prev_idx = 0
        while True:
            prev_idx, cmd = self.find_cmd(LC_SEGMENT, prev_idx)
            cmd = SegmentCommand.from_buffer_copy(cmd)

            if cmd.segname.decode() == name:
                return cmd

DSC_MAGIC = b"dyld_v1   armv7"

class DyldCacheHeader(Structure):
    _fields_ = [
        ("magic", ARRAY(c_char, 16)),
        ("mappingOffset", c_uint32),
        ("mappingCount", c_uint32),
        ("imagesOffset", c_uint32),
        ("imagesCount", c_uint32),
        ("dyldBaseAddress", c_uint64),
        ("codeSignatureOffset", c_uint64),
        ("codeSignatureSize", c_uint64)
        # ...
    ]

    @classmethod
    def load(cls, data: bytes) -> "DyldCacheHeader":
        c = cls.from_buffer_copy(data[:sizeof(DyldCacheHeader)])
        if c.magic != DSC_MAGIC:
            raise YolosignError("bad magic in dyld shared cache header")

        return c

class DyldSharedCache:
    def __init__(self, fd):
        self.fd = fd

        self.fd.seek(0)
        self.header = DyldCacheHeader.load(
            self.fd.read(sizeof(DyldCacheHeader)))

CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSMAGIC_CODEDIRECTORY = 0xfade0c02
CSSLOT_CODEDIRECTORY = 0

class CS_BlobIndex(BigEndianStructure):
    _fields_ = [
        ("type", c_uint32),
        ("offset", c_uint32)
    ]

class CS_SuperBlob(BigEndianStructure):
    _fields_ = [
        ("magic", c_uint32),
        ("length", c_uint32),
        ("count", c_uint32)
    ]

    @classmethod
    def load(cls, data: bytes) -> "CS_SuperBlob":
        c = cls.from_buffer_copy(data[:sizeof(CS_SuperBlob)])
        if c.magic != CSMAGIC_EMBEDDED_SIGNATURE:
            raise YolosignError("bad magic in code signature SuperBlob")

        return c

class CS_CodeDirectory(BigEndianStructure):
    _fields_ = [
        ("magic", c_uint32),
        ("length", c_uint32),
        ("version", c_uint32),
        ("flags", c_uint32),
        ("hashOffset", c_uint32),
        ("identOffset", c_uint32),
        ("nSpecialSlots", c_uint32),
        ("nCodeSlots", c_uint32)
        # ...
    ]

    @classmethod
    def load(cls, data: bytes) -> "CS_CodeDirectory":
        c = cls.from_buffer_copy(data[:sizeof(CS_CodeDirectory)])
        if c.magic != CSMAGIC_CODEDIRECTORY:
            raise YolosignError("bad magic in code signature CodeDirectory")

        return c

def off2page(off: int) -> int:
    return off // PAGE_SIZE

def yolosign(path: Path, pages: List[int]):
    with open(path, "r+b") as f:
        try:
            dsc = DyldSharedCache(f)

            off = dsc.header.codeSignatureOffset
            size = dsc.header.codeSignatureSize

            if size == 0:
                size = os.fstat(f.fileno()).st_size - off

        except YolosignError:
            macho = MachO(f)
            _, c = macho.find_cmd(LC_CODE_SIGNATURE)
            code_signature_cmd = LinkeditDataCommand.from_buffer_copy(c)

            off = code_signature_cmd.dataoff
            size = code_signature_cmd.datasize

        f.seek(off)
        code_signature = bytearray(f.read(size))

        sb = CS_SuperBlob.load(code_signature)

        cd = None
        for i in range(sb.count):
            bi = CS_BlobIndex.from_buffer_copy(
                code_signature, sizeof(CS_SuperBlob) + i * sizeof(CS_BlobIndex))

            if bi.type == CSSLOT_CODEDIRECTORY:
                cd = CS_CodeDirectory.load(code_signature[bi.offset:])
                break

        if cd is None:
            raise YolosignError("no CodeDirectory found?!")

        for p in pages:
            if p > cd.nCodeSlots:
                raise YolosignError("CodeDirectory is too small to contain page %d" % page)

            pageoff = PAGE_SIZE * p

            f.seek(pageoff)
            page = f.read(PAGE_SIZE)

            h_obj = hashlib.sha1(page)
            h_off = bi.offset + cd.hashOffset + h_obj.digest_size * p
            code_signature[h_off:h_off+h_obj.digest_size] = h_obj.digest()

        f.seek(off)
        f.write(code_signature)
