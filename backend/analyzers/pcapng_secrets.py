"""Prepare section-local PCAPNG secrets before tshark dissects packets.

DSBs can be written after their TLS records. A second tshark dissection pass
does not reliably reload those sessions. Move the existing DSBs to the front
of their own section in a private disposable copy; never change the artifact.
"""
from __future__ import annotations

import os
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator

_SHB = b'\x0a\x0d\x0d\x0a'
_CHUNK_SIZE = 1024 * 1024


@dataclass
class _Section:
    start: int
    header_end: int
    end: int
    secrets: list[tuple[int, int]] = field(default_factory=list)


def _scan(source: BinaryIO, size: int) -> list[_Section]:
    sections: list[_Section] = []
    offset = 0
    endian = '<'
    while offset < size:
        source.seek(offset)
        header = source.read(12)
        if len(header) < 12:
            raise ValueError(f'Invalid PCAPNG: truncated block at {offset}')
        is_section = header[:4] == _SHB
        if is_section:
            if header[8:12] == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif header[8:12] == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise ValueError(f'Invalid PCAPNG: byte-order magic at {offset}')
        kind, length = struct.unpack(endian + 'II', header[:8])
        minimum = 28 if is_section else 20 if kind == 10 else 12
        if length < minimum or length % 4 or length > size - offset:
            raise ValueError(f'Invalid PCAPNG: block length at {offset}')
        source.seek(offset + length - 4)
        trailer = source.read(4)
        if struct.unpack(endian + 'I', trailer)[0] != length:
            raise ValueError(f'Invalid PCAPNG: block trailer at {offset}')
        if is_section:
            if sections:
                sections[-1].end = offset
            sections.append(_Section(offset, offset + length, size))
        elif not sections:
            raise ValueError('Invalid PCAPNG: missing section header')
        if kind == 10:
            source.seek(offset + 8)
            _, secret_length = struct.unpack(endian + 'II', source.read(8))
            if secret_length + (-secret_length % 4) > length - 20:
                raise ValueError(f'Invalid PCAPNG: secret length at {offset}')
            sections[-1].secrets.append((offset, offset + length))
        offset += length
    return sections


def _copy_range(source: BinaryIO, target: BinaryIO, start: int, end: int) -> None:
    source.seek(start)
    remaining = end - start
    while remaining:
        chunk = source.read(min(remaining, _CHUNK_SIZE))
        if not chunk:
            raise ValueError('Invalid PCAPNG: source changed during preparation')
        target.write(chunk)
        remaining -= len(chunk)


@contextmanager
def prepared_pcapng(path: str) -> Iterator[str]:
    """Yield original PCAP/no-secret input or a private DSB-first PCAPNG copy."""
    with open(path, 'rb') as source:
        if source.read(4) != _SHB:
            yield path
            return
        size = os.fstat(source.fileno()).st_size
        sections = _scan(source, size)
        if not any(s.secrets for s in sections):
            yield path
            return
        with tempfile.TemporaryDirectory(prefix='ecapture-secrets-') as directory:
            temporary = Path(directory) / 'prepared.pcapng'
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as target:
                for section in sections:
                    _copy_range(source, target, section.start, section.header_end)
                    for start, end in section.secrets:
                        _copy_range(source, target, start, end)
                    cursor = section.header_end
                    for start, end in section.secrets:
                        _copy_range(source, target, cursor, start)
                        cursor = end
                    _copy_range(source, target, cursor, section.end)
            yield str(temporary)
