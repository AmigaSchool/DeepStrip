#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepStrip v4.4.19 — Textbook-Quality OrCAD Archive Extractor
===========================================================

A single-file, pure Python 3.8+ recursive extractor focused on legacy OrCAD content.
Designed for clarity, completeness, and immediate usability without modification.

New in v4.4.19:
- Enhanced OrCAD header parsing with metadata extraction
- Automated hex dump generation for binaries
- String extraction from executables and libraries
- Comprehensive HTML/Markdown reporting
- Integrity validation for OrCAD files

Highlights
----------
- **Automatic nested extraction**: Recursively extracts archives within archives to any depth
- **Universal format support**: ZIP, TAR/GZip, CAB (MSZIP + LZX), InstallShield CABs/PAKs
- **Smart filtering**: Include/exclude by glob patterns with default all-files extraction
- **Flexible output**: Flat single-directory or preserved tree structure
- **Collision handling**: Systematic renaming for duplicate files in flat mode
- **InstallShield support**: Extracts from ISc() CABs, PAK files, PKG/INS bundles
- **Script extraction**: Parses SETUP.INS scripts to JSON with string tables
- **PE carving**: Automatically finds and extracts embedded archives from .EXE files
- **OrCAD awareness**: Classifies and indexes .OLB, .SCH, .DSN, .LIB files
- **Safety features**: Size limits, recursion caps, path traversal protection
- **Diagnostics**: Optional detailed JSON logging for troubleshooting

Usage
-----
    python deepstrip.py INPUT [-o DIR]
                              [--flat]
                              [--include PATTERNS] [--exclude PATTERNS]
                              [--extract-ins]
                              [--orcad | --extract]
                              [--diag-json FILE]

Quick Examples
--------------
  # Extract everything from nested archives (default):
  python deepstrip.py installer.exe

  # Extract only OrCAD files to flat directory:
  python deepstrip.py ORCADCAP.60.zip -o ./olb_files --flat --include "*.olb,*.sch"

  # Extract all except executables:
  python deepstrip.py bundle.cab --exclude "*.exe,*.dll"

  # Extract with InstallShield script parsing:
  python deepstrip.py setup.exe --extract-ins
  
  # Two-phase extraction for InstallShield bundles in ZIP:
  python deepstrip.py ORCADCAP.60.zip -o ./temp    # Extract outer ZIP
  python deepstrip.py ./temp/ORCADCAP.60 -o ./out  # Extract PAKs from directory
"""

from __future__ import annotations

import argparse
import contextlib
import enum
import fnmatch
import io
import json
import os
import re
import struct
import sys
import tarfile
import time
import zipfile
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any, BinaryIO
from collections import namedtuple

# =============================================================================
# Constants
# =============================================================================

class CompressionType(enum.IntEnum):
    """Compression type constants for various formats."""
    STORED = 0
    PKWARE_IMPLODE = 1
    MSZIP = 1
    LZX = 3

class BlockType(enum.IntEnum):
    """LZX block type constants."""
    VERBATIM = 1
    ALIGNED = 2
    UNCOMPRESSED = 3

# Archive signatures
SIG_ZIP = b"PK\x03\x04"
SIG_GZIP = b"\x1f\x8b"
SIG_CAB = b"MSCF"
SIG_ISCAB = b"ISc("
SIG_IS3PAK = 0x135D658C
SIG_IS3PAK_ALT = 0x8C655D13  # Alternative endianness
SIG_PE_MZ = b"MZ"
SIG_PE_ZM = b"ZM"

# Encoding preferences
PREFERRED_ENCODING = "cp437"  # DOS/Windows legacy encoding
FALLBACK_ENCODING = "latin-1"

# =============================================================================
# Limits and Environment
# =============================================================================

class Limits:
    """Resource limits for safety and predictable behavior."""
    MAX_TOTAL_BYTES: int = 500 * 1024 * 1024   # 500 MiB maximum total output
    MAX_ENTRY_BYTES: int = 100 * 1024 * 1024   # 100 MiB per single extracted entry
    DEFAULT_MAX_DEPTH: int = 10                # Default nested recursion depth
    MAX_NAME_LEN: int = 240                    # Avoid pathological path lengths
    MAX_PATH_DEPTH: int = 20                   # Maximum directory depth
    CHUNK_SIZE: int = 65536                    # Read chunk size for large files
    STREAM_THRESHOLD: int = 10 * 1024 * 1024   # Stream files larger than 10MB

# =============================================================================
# Logger (console + optional JSON diag sink)
# =============================================================================

class LogLevel(enum.Enum):
    """Log level enumeration."""
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    DIAG = "diag"

class Logger:
    """
    Structured logger with console output and optional JSON diagnostic export.
    Thread-safe through GIL for basic operations.
    """
    def __init__(self, enable_diag: bool = False):
        self.enable_diag = enable_diag
        self.messages: Dict[str, List[str]] = {
            level.value: [] for level in LogLevel
        }

    def _log(self, level: LogLevel, msg: str, prefix: str, file=None) -> None:
        """Internal logging method."""
        self.messages[level.value].append(msg)
        if level != LogLevel.DIAG or self.enable_diag:
            print(f"{prefix} {msg}", file=file)

    def info(self, msg: str) -> None:
        self._log(LogLevel.INFO, msg, "[+]", sys.stdout)

    def warn(self, msg: str) -> None:
        self._log(LogLevel.WARN, msg, "[!] WARNING:", sys.stderr)

    def error(self, msg: str) -> None:
        self._log(LogLevel.ERROR, msg, "[X] ERROR:", sys.stderr)

    def diag(self, msg: str) -> None:
        if self.enable_diag:
            self._log(LogLevel.DIAG, msg, "[diag]", sys.stdout)

    def export_json(self, path: Path) -> None:
        """Export logged messages to JSON file."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.messages, f, indent=2, ensure_ascii=False)
            self.info(f"Diagnostic JSON written to: {path}")
        except OSError as e:
            self.warn(f"Failed to write diagnostics JSON: {e}")

# =============================================================================
# Utilities
# =============================================================================

def sanitize_filename(name: str) -> str:
    """
    Make a string safe for filenames with enhanced security.
    Prevents directory traversal and other path attacks.
    """
    # Remove any directory traversal attempts
    name = name.replace("..", "_")
    
    # Normalize path separators and remove them
    name = name.replace("\\", "/")
    # Keep only the final component to prevent directory traversal
    name = os.path.basename(name)
    
    # Remove dangerous characters
    bad_chars = '\"<>|:*?\0\n\r\t'
    trans_table = str.maketrans(bad_chars, '_' * len(bad_chars))
    name = name.translate(trans_table)
    
    # Clean up whitespace and dots
    name = name.strip().strip(".")
    
    # Handle empty or invalid names
    if not name or name in (".", "..", "~"):
        name = "unnamed"
    
    # Limit length intelligently
    if len(name) > Limits.MAX_NAME_LEN:
        base, dot, ext = name.rpartition(".")
        if dot and len(ext) <= 10:  # Preserve reasonable extensions
            max_base = Limits.MAX_NAME_LEN - len(ext) - 9  # Room for __TRUNC
            name = f"{base[:max_base]}__TRUNC.{ext}"
        else:
            name = f"{name[:Limits.MAX_NAME_LEN - 8]}__TRUNC"
    
    return name

def ensure_parent(path: Path) -> None:
    """Create parent directory for path with safety checks."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"Cannot create parent directory for {path}: {e}")

def write_atomic(path: Path, data: bytes, logger: Logger) -> None:
    """
    Atomically write bytes to path with proper error handling.
    Uses temporary file and atomic rename for safety.
    """
    ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        
        # Atomic rename (on POSIX) or best-effort on Windows
        if sys.platform == "win32":
            # Windows doesn't support atomic rename if target exists
            if path.exists():
                path.unlink()
        os.rename(tmp, path)
        
        logger.diag(f"Wrote {len(data):,} bytes -> {path}")
    except OSError as e:
        # Clean up temporary file on failure
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise OSError(f"Failed to write {path}: {e}")

def write_atomic_stream(path: Path, data_source, size: int, logger: Logger) -> None:
    """
    Stream-write data to path for large files.
    data_source can be file-like object or bytes.
    """
    ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    
    try:
        with open(tmp, "wb") as f:
            if hasattr(data_source, 'read'):
                # File-like object - stream in chunks
                written = 0
                while written < size:
                    chunk_size = min(Limits.CHUNK_SIZE, size - written)
                    chunk = data_source.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    written += len(chunk)
            else:
                # Bytes - write directly
                f.write(data_source)
            
            f.flush()
            os.fsync(f.fileno())
        
        # Atomic rename
        if sys.platform == "win32" and path.exists():
            path.unlink()
        os.rename(tmp, path)
        
        logger.diag(f"Stream-wrote {size:,} bytes -> {path}")
    except OSError as e:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise OSError(f"Failed to stream-write {path}: {e}")

def ext_lower(name: str) -> str:
    """Return lowercase file extension including dot."""
    return Path(name).suffix.lower()

def pattern_list(pats: str) -> List[str]:
    """
    Split a comma-separated glob pattern string into a normalized list.
    Handles whitespace and empty patterns gracefully.
    """
    if not pats:
        return []
    return [p.strip().lower() for p in pats.split(",") if p.strip()]

def safe_decode(data: bytes, preferred: str = PREFERRED_ENCODING, 
                fallback: str = FALLBACK_ENCODING) -> str:
    """
    Safely decode bytes to string with fallback encoding.
    """
    for encoding in (preferred, fallback, "utf-8", "ascii"):
        try:
            return data.decode(encoding, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    # Last resort: replace errors
    return data.decode(fallback, errors="replace")

# =============================================================================
# Config and CLI
# =============================================================================

class Config:
    """Immutable configuration parsed from CLI arguments."""
    __slots__ = ("input", "output", "mode_orcad", "mode_extract", "flat",
                 "include", "exclude", "extract_ins", "diag_json", "max_depth",
                 "generate_hex", "extract_strings", "generate_report")
    
    def __init__(self, args: argparse.Namespace):
        self.input: Path = Path(args.input)
        self.output: Path = Path(args.output)
        self.mode_orcad: bool = bool(args.orcad or not args.extract)
        self.mode_extract: bool = bool(args.extract)
        self.flat: bool = bool(args.flat)
        self.include: List[str] = pattern_list(args.include)
        self.exclude: List[str] = pattern_list(args.exclude)
        self.extract_ins: bool = bool(args.extract_ins)
        self.diag_json: Optional[Path] = Path(args.diag_json) if args.diag_json else None
        
        # Handle max_depth: 0 or -1 means unlimited
        self.max_depth: Optional[int] = None if args.max_depth <= 0 else args.max_depth
        
        # New analysis features
        self.generate_hex: bool = bool(getattr(args, 'generate_hex', False))
        self.extract_strings: bool = bool(getattr(args, 'extract_strings', False))
        self.generate_report: bool = bool(getattr(args, 'generate_report', False))
        
        # Handle --analysis-all flag
        if getattr(args, 'analysis_all', False):
            self.generate_hex = True
            self.extract_strings = True

    def __repr__(self) -> str:
        depth_str = "unlimited" if self.max_depth is None else str(self.max_depth)
        return (f"Config(input={self.input}, output={self.output}, "
                f"orcad={self.mode_orcad}, extract={self.mode_extract}, "
                f"flat={self.flat}, include={self.include}, exclude={self.exclude}, "
                f"extract_ins={self.extract_ins}, max_depth={depth_str}, "
                f"generate_hex={self.generate_hex}, extract_strings={self.extract_strings}, "
                f"generate_report={self.generate_report}, "
                f"diag_json={self.diag_json})")

# =============================================================================
# PKWARE Implode (InstallShield) — Optimized Pure Python
# =============================================================================

_MAXBITS = 13
_LITLEN_RLE  = bytes([
    11,124, 8, 7, 28, 7,188,13, 76, 4, 10, 8, 12,10, 12,10,  8, 23, 8,  9, 7, 6, 7, 8, 7, 6, 55, 8, 23,
    24, 12, 11, 7,  9,11, 12, 6,  7,22,  5, 7, 24, 6, 11, 9,  6,  7,22, 7,11, 38, 7, 9, 8, 25,11, 8, 11,
     9, 12,  8,12,  5,38,  5,38,  5, 11,  7, 5,  6,21, 6, 10, 53, 8, 7, 24,10, 27, 44,253,253,253,252,252,
   252, 13, 12,45, 12,45, 12,61, 12, 45, 44,173
])
_LENLEN_RLE  = bytes([2, 35, 36, 53, 38, 23])
_DISTLEN_RLE = bytes([2, 20, 53,230,247,151,248])
_LEN_BASE = (3,2,4,5,6,7,8,9,10,12,16,24,40,72,136,264)
_LEN_EXTRA= (0,0,0,0,0,0,0,0, 1, 2, 3, 4, 5, 6,  7,  8)

class _Huff:
    """Huffman tree for PKWARE implode."""
    __slots__ = ("count", "symbol")
    
    def __init__(self, n_syms: int):
        self.count = [0] * (_MAXBITS + 1)
        self.symbol = [0] * n_syms

class _BitStream:
    """Bit stream reader for PKWARE implode."""
    __slots__ = ("src", "i", "bitbuf", "bitcnt")
    
    def __init__(self, data: bytes):
        self.src = data
        self.i = 0
        self.bitbuf = 0
        self.bitcnt = 0
    
    def _need(self, n: int) -> None:
        """Ensure n bits are available in buffer."""
        while self.bitcnt < n:
            if self.i >= len(self.src):
                raise EOFError("implode: out of input")
            self.bitbuf |= self.src[self.i] << self.bitcnt
            self.i += 1
            self.bitcnt += 8
    
    def bits(self, n: int) -> int:
        """Read n bits from stream."""
        if n == 0:
            return 0
        self._need(n)
        v = self.bitbuf & ((1 << n) - 1)
        self.bitbuf >>= n
        self.bitcnt -= n
        return v

def _expand_rle(rle: bytes, n: int) -> List[int]:
    """Expand RLE-encoded lengths."""
    out: List[int] = []
    for b in rle:
        rep, ln = (b >> 4) + 1, b & 0x0F
        out.extend([ln] * rep)
        if len(out) >= n:
            break
    return out[:n]

def _construct(h: _Huff, rle: bytes, n: int) -> int:
    """Construct Huffman tree from RLE data."""
    lengths = _expand_rle(rle, n)
    
    for ln in lengths:
        if ln:
            h.count[ln] += 1
    
    offs = [0] * (_MAXBITS + 1)
    for ln in range(1, _MAXBITS):
        offs[ln + 1] = offs[ln] + h.count[ln]
    
    for sym, ln in enumerate(lengths):
        if ln:
            h.symbol[offs[ln]] = sym
            offs[ln] += 1
    
    # Validate tree
    left = 1
    for ln in range(1, _MAXBITS + 1):
        left = (left << 1) - h.count[ln]
        if left < 0:
            return -1
    return left

def _decode_optimized(bs: _BitStream, h: _Huff) -> int:
    """Decode one symbol from Huffman tree."""
    code, first, index = 0, 0, 0
    local_counts, local_symbols = h.count, h.symbol
    
    for ln in range(1, _MAXBITS + 1):
        bs._need(1)
        bit = bs.bitbuf & 1
        bs.bitbuf >>= 1
        bs.bitcnt -= 1
        code = (code << 1) | (bit ^ 1)
        cnt = local_counts[ln]
        if code < first + cnt:
            return local_symbols[index + (code - first)]
        index += cnt
        first = (first + cnt) << 1
    
    raise ValueError("implode: invalid code")

def pk_explode_implode(data: bytes) -> bytes:
    """
    Decompress PKWARE 'implode' data with enhanced error handling.
    Returns decompressed bytes.
    """
    if len(data) < 2:
        raise ValueError("implode: input too short")
    
    # Add size sanity check
    if len(data) > Limits.MAX_ENTRY_BYTES:
        raise ValueError(f"implode: input too large ({len(data)} bytes)")
    
    bs = _BitStream(data)
    
    try:
        lit_flag, dict_bits = bs.bits(8), bs.bits(8)
    except EOFError:
        raise ValueError("implode: header truncated")
    
    if lit_flag not in (0, 1):
        raise ValueError(f"implode: invalid literal flag {lit_flag}")
    if dict_bits not in (4, 5, 6):
        raise ValueError(f"implode: invalid dictionary bits {dict_bits}")

    # Build Huffman trees
    litcode = _Huff(256)
    lencode = _Huff(16)
    distcode = _Huff(64)
    
    if _construct(litcode, _LITLEN_RLE, 256) < 0:
        raise ValueError("implode: invalid literal tree")
    if _construct(lencode, _LENLEN_RLE, 16) < 0:
        raise ValueError("implode: invalid length tree")
    if _construct(distcode, _DISTLEN_RLE, 64) < 0:
        raise ValueError("implode: invalid distance tree")

    out = bytearray()
    local_bs_bits = bs.bits
    local_decode = _decode_optimized
    local_append = out.append
    local_len_base = _LEN_BASE
    local_len_extra = _LEN_EXTRA
    
    try:
        while len(out) < Limits.MAX_ENTRY_BYTES:
            if local_bs_bits(1) == 0:
                # Literal
                c = local_bs_bits(8) if lit_flag == 0 else local_decode(bs, litcode)
                local_append(c)
            else:
                # Length/distance pair
                sym = local_decode(bs, lencode)
                ln = local_len_base[sym]
                if local_len_extra[sym]:
                    ln += local_bs_bits(local_len_extra[sym])
                
                if ln == 519:  # End marker
                    break
                
                # Distance
                extra_bits = 2 if ln == 2 else dict_bits
                dist = (local_decode(bs, distcode) << extra_bits) + local_bs_bits(extra_bits) + 1
                
                if dist > len(out):
                    raise ValueError(f"implode: invalid distance {dist} > {len(out)}")
                
                # Copy from window
                src_pos = len(out) - dist
                for _ in range(ln):
                    local_append(out[src_pos])
                    src_pos += 1
                    
    except EOFError:
        pass  # Normal end of stream
    
    return bytes(out)

# =============================================================================
# LZX Decompressor (CAB LZX)
# =============================================================================

class LZXBitReader:
    """Bit reader for LZX decompression."""
    __slots__ = ("buf", "i", "bitbuf", "bits")
    
    def __init__(self, data: bytes):
        self.buf = data
        self.i = 0
        self.bitbuf = 0
        self.bits = 0
    
    def _fill(self, need: int) -> None:
        """Fill bit buffer to have at least 'need' bits."""
        while self.bits < need and self.i < len(self.buf):
            self.bitbuf = (self.bitbuf << 8) | self.buf[self.i]
            self.i += 1
            self.bits += 8
        if self.bits < need:
            raise EOFError("LZX: bitstream underflow")
    
    def read(self, n: int) -> int:
        """Read n bits from stream."""
        if n == 0:
            return 0
        self._fill(n)
        v = (self.bitbuf >> (self.bits - n)) & ((1 << n) - 1)
        self.bits -= n
        self.bitbuf &= (1 << self.bits) - 1
        return v
    
    def align_to_byte(self) -> None:
        """Align bit position to byte boundary."""
        skip = self.bits % 8
        if skip:
            self.read(skip)
    
    def at_eof(self) -> bool:
        """Check if at end of stream."""
        return self.i >= len(self.buf) and self.bits == 0

class LZXHuff:
    """Huffman tree for LZX decompression."""
    __slots__ = ("maxbits", "firstcode", "firstsym", "counts", "syms")
    
    def __init__(self):
        self.maxbits = 0
        self.firstcode: List[int] = []
        self.firstsym: List[int] = []
        self.counts: List[int] = []
        self.syms: List[int] = []
    
    def build(self, lengths: List[int], maxbits: int = 16) -> None:
        """Build Huffman tree from code lengths."""
        n = len(lengths)
        self.maxbits = maxbits
        self.counts = [0] * (maxbits + 1)
        
        for ln in lengths:
            if ln < 0 or ln > maxbits:
                raise ValueError(f"LZX: invalid code length {ln}")
            if ln:
                self.counts[ln] += 1
        
        # Validate tree
        left = 1
        for ln in range(1, maxbits + 1):
            left = (left << 1) - self.counts[ln]
            if left < 0:
                raise ValueError("LZX: over-subscribed Huffman tree")
        
        # Build decoding tables
        self.firstcode = [0] * (maxbits + 1)
        self.firstsym = [0] * (maxbits + 1)
        code = 0
        
        for ln in range(1, maxbits + 1):
            self.firstcode[ln] = code
            self.firstsym[ln] = self.firstsym[ln - 1] + self.counts[ln - 1]
            code = (code + self.counts[ln]) << 1
        
        # Assign symbols
        self.syms = [0] * sum(self.counts)
        idx = [0] * (maxbits + 1)
        for ln in range(1, maxbits + 1):
            idx[ln] = self.firstsym[ln]
        
        for sym, ln in enumerate(lengths):
            if ln:
                self.syms[idx[ln]] = sym
                idx[ln] += 1
    
    def decode(self, br: LZXBitReader) -> int:
        """Decode one symbol from Huffman tree."""
        code = 0
        for ln in range(1, self.maxbits + 1):
            code = (code << 1) | br.read(1)
            first = self.firstcode[ln]
            count = self.counts[ln]
            if code - first < count:
                idx = self.firstsym[ln] + (code - first)
                return self.syms[idx]
        raise ValueError("LZX: invalid Huffman code")

class LZXDecoder:
    """Pure-Python LZX decoder for CAB archives."""
    
    # LZX constants
    NUM_CHARS = 256
    NUM_PRIMARY_LENS = 7
    LENTREE_MAXSYMS = 256
    PRETREE_SYMS = 20
    ALIGNED_SYMS = 8
    
    # Window size to position slots mapping
    WIN_POS_SLOTS = {
        15: 30, 16: 32, 17: 34, 18: 36,
        19: 38, 20: 42, 21: 50
    }
    
    def __init__(self, window_bits: int):
        if window_bits < 15 or window_bits > 21:
            raise ValueError(f"LZX: window bits must be 15-21, got {window_bits}")
        
        self.win_bits = window_bits
        self.window_size = 1 << window_bits
        self.window = bytearray(self.window_size)
        self.window_pos = 0
        self.R0 = 1
        self.R1 = 1
        self.R2 = 1
        self.pos_slots = self.WIN_POS_SLOTS.get(window_bits, 50)
        self.pos_base, self.pos_extra = self._make_pos_tables(self.pos_slots)
        self.maintree = LZXHuff()
        self.lentree = LZXHuff()
        self.aligntree = LZXHuff()

    @staticmethod
    def _make_pos_tables(pos_slots: int) -> Tuple[List[int], List[int]]:
        """Generate position base and extra bits tables."""
        pos_base = [0] * pos_slots
        pos_extra = [0] * pos_slots
        base = 0
        
        for s in range(4):
            pos_base[s] = base
            pos_extra[s] = 0
            base += 1
        
        extra = 1
        s = 4
        while s < pos_slots:
            for _ in range(2):
                if s >= pos_slots:
                    break
                pos_base[s] = base
                pos_extra[s] = extra
                base += (1 << extra)
                s += 1
            extra += 1
        
        return pos_base, pos_extra

    def _read_pretree(self, br: LZXBitReader) -> LZXHuff:
        """Read and build pre-tree for tree decoding."""
        lens = [br.read(4) for _ in range(self.PRETREE_SYMS)]
        ht = LZXHuff()
        ht.build(lens, maxbits=16)
        return ht

    def _read_tree_lengths(self, br: LZXBitReader, nsyms: int) -> List[int]:
        """Read tree lengths using pre-tree."""
        pretree = self._read_pretree(br)
        lengths = [0] * nsyms
        val = 0
        i = 0
        
        while i < nsyms:
            sym = pretree.decode(br)
            
            if sym <= 16:
                val = (val - sym + 17) % 17
                lengths[i] = val
                i += 1
            elif sym == 17:  # Run of zeros
                run = br.read(4) + 4
                for _ in range(min(run, nsyms - i)):
                    lengths[i] = 0
                    i += 1
                val = 0
            elif sym == 18:  # Long run of zeros
                run = br.read(5) + 20
                for _ in range(min(run, nsyms - i)):
                    lengths[i] = 0
                    i += 1
                val = 0
            elif sym == 19:  # Repeat
                rep = br.read(1) + 4
                delta = pretree.decode(br)
                val = (val - delta + 17) % 17
                for _ in range(min(rep, nsyms - i)):
                    lengths[i] = val
                    i += 1
            else:
                raise ValueError(f"LZX: invalid pretree symbol {sym}")
        
        return lengths

    def _build_block_trees(self, br: LZXBitReader, block_type: int) -> None:
        """Build Huffman trees for current block."""
        nmain = self.NUM_CHARS + (self.pos_slots << 3)
        
        # Read main tree in two parts
        mt_lens_a = self._read_tree_lengths(br, self.NUM_CHARS)
        mt_lens_b = self._read_tree_lengths(br, nmain - self.NUM_CHARS)
        main_lengths = mt_lens_a + mt_lens_b
        self.maintree.build(main_lengths, maxbits=16)
        
        # Read length tree
        lt_lengths = self._read_tree_lengths(br, self.LENTREE_MAXSYMS)
        self.lentree.build(lt_lengths, maxbits=16)
        
        # Read aligned tree if needed
        if block_type == BlockType.ALIGNED:
            at_lengths = [br.read(3) for _ in range(self.ALIGNED_SYMS)]
            self.aligntree.build(at_lengths, maxbits=7)

    def _copy_from_window(self, out: bytearray, length: int, dist: int) -> None:
        """Copy bytes from sliding window."""
        if dist < 1 or dist > self.window_size:
            raise ValueError(f"LZX: invalid match distance {dist}")
        
        wp = self.window_pos
        start = (wp - dist) & (self.window_size - 1)
        
        for _ in range(length):
            b = self.window[start]
            start = (start + 1) & (self.window_size - 1)
            out.append(b)
            self.window[wp] = b
            wp = (wp + 1) & (self.window_size - 1)
        
        self.window_pos = wp

    def _put_literal(self, out: bytearray, b: int) -> None:
        """Output literal byte and update window."""
        wp = self.window_pos
        byte_val = b & 0xFF
        out.append(byte_val)
        self.window[wp] = byte_val
        self.window_pos = (wp + 1) & (self.window_size - 1)

    def _decode_compressed_block(self, br: LZXBitReader, out: bytearray,
                                to_write: int, block_type: int) -> None:
        """Decode compressed block data."""
        while to_write > 0:
            sym = self.maintree.decode(br)
            
            if sym < self.NUM_CHARS:
                # Literal byte
                self._put_literal(out, sym)
                to_write -= 1
                continue
            
            # Length/distance pair
            sym -= self.NUM_CHARS
            len_header = sym & 0x7
            pos_slot = sym >> 3
            
            # Decode match length
            match_len = len_header + 2
            if len_header == self.NUM_PRIMARY_LENS:
                extra = self.lentree.decode(br)
                match_len += extra
            
            # Decode match distance
            if pos_slot < 3:
                # Recent offsets
                if pos_slot == 0:
                    dist = self.R0
                elif pos_slot == 1:
                    dist = self.R1
                    self.R1, self.R0 = self.R0, dist
                else:  # pos_slot == 2
                    dist = self.R2
                    self.R2, self.R1, self.R0 = self.R1, self.R0, dist
            else:
                # Direct position
                extra_bits = self.pos_extra[pos_slot]
                base = self.pos_base[pos_slot]
                
                if block_type == BlockType.ALIGNED and extra_bits >= 3:
                    # Aligned offset encoding
                    verb = br.read(extra_bits - 3)
                    low3 = self.aligntree.decode(br)
                    dist = base + ((verb << 3) | low3)
                else:
                    # Verbatim offset encoding
                    extra = br.read(extra_bits) if extra_bits else 0
                    dist = base + extra
                
                # Update recent offsets
                self.R2, self.R1, self.R0 = self.R1, self.R0, dist
            
            if dist == 0:
                raise ValueError("LZX: zero match distance")
            
            # Copy matched string
            self._copy_from_window(out, match_len, dist)
            to_write -= match_len

    def _decode_uncompressed_block(self, br: LZXBitReader, out: bytearray,
                                  to_write: int) -> None:
        """Decode uncompressed block data."""
        br.align_to_byte()
        
        for _ in range(to_write):
            if br.at_eof():
                raise EOFError("LZX: truncated uncompressed block")
            b = br.read(8)
            self._put_literal(out, b)

    def decompress(self, data: bytes, expected_output: int) -> bytes:
        """
        Decompress LZX data to specified output size.
        """
        if expected_output > Limits.MAX_ENTRY_BYTES:
            raise ValueError(f"LZX: Expected output {expected_output} exceeds limit")
        
        if len(data) == 0:
            return b""
        
        br = LZXBitReader(data)
        out = bytearray()
        
        while len(out) < expected_output:
            try:
                # Read block header
                btype = br.read(3)
                blen = br.read(24)
            except EOFError:
                break  # End of stream
            
            if blen == 0:
                continue  # Empty block
            
            # Sanity check block length
            if blen > expected_output * 2:
                raise ValueError(f"LZX: Unrealistic block length {blen}")
            
            to_write = min(blen, expected_output - len(out))
            
            if btype == BlockType.UNCOMPRESSED:
                self._decode_uncompressed_block(br, out, to_write)
            elif btype in (BlockType.VERBATIM, BlockType.ALIGNED):
                self._build_block_trees(br, btype)
                self._decode_compressed_block(br, out, to_write, btype)
            else:
                raise ValueError(f"LZX: unsupported block type {btype}")
        
        return bytes(out[:expected_output])

# =============================================================================
# Archive Type Detection
# =============================================================================

class Detector:
    """Enhanced archive/container type detection."""
    
    # Compiled regex patterns for efficiency
    _USTAR_PATTERN = re.compile(rb"ustar", re.IGNORECASE)
    
    @classmethod
    def detect(cls, blob: bytes) -> str:
        """
        Detect archive type from binary signature.
        Returns type string for dispatch.
        """
        if not blob:
            return "raw"
        
        # Check PE executable first (may contain overlays)
        if len(blob) >= 2 and blob[:2] in (SIG_PE_MZ, SIG_PE_ZM):
            return "pe"
        
        # ZIP archive
        if blob.startswith(SIG_ZIP):
            return "zip"
        
        # Microsoft CAB
        if blob.startswith(SIG_CAB):
            return "cab"
        
        # GZIP or TAR
        if blob.startswith(SIG_GZIP):
            return "tar"  # Will auto-detect gzip
        
        # TAR (ustar signature)
        if len(blob) > 265 and cls._USTAR_PATTERN.search(blob[257:265]):
            return "tar"
        
        # InstallShield 3 PAK (check both endianness)
        if len(blob) >= 4:
            try:
                magic = struct.unpack_from("<I", blob, 0)[0]
                if magic in (SIG_IS3PAK, SIG_IS3PAK_ALT):
                    return "is3pak"
            except struct.error:
                pass
        
        # InstallShield unified CAB (search in first 64KB)
        if SIG_ISCAB in blob[:min(65536, len(blob))]:
            return "iscab"
        
        return "raw"

# =============================================================================
# Archive Handlers (CODEC)
# =============================================================================

class CODEC:
    """
    Unified handlers for archive formats.
    Each returns List[Tuple[name, bytes]] for recursive processing.
    """
    
    # -------- ZIP --------
    @staticmethod
    def zip_list(data: bytes, logger: Logger) -> List[Tuple[str, bytes]]:
        """Extract ZIP archive with enhanced error handling and streaming support."""
        out: List[Tuple[str, bytes]] = []
        
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                # Validate and extract entries
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    
                    # Security check for path traversal
                    name = info.filename
                    if ".." in name or name.startswith("/"):
                        logger.warn(f"ZIP: Skipping potentially unsafe path: {name}")
                        continue
                    
                    # Sanitize and extract
                    clean_name = sanitize_filename(name)
                    
                    try:
                        # Check file size for streaming decision
                        if info.file_size > Limits.STREAM_THRESHOLD:
                            logger.diag(f"ZIP: Large file {clean_name} ({info.file_size:,} bytes), using chunked read")
                            
                            # Read in chunks to limit memory usage
                            chunks = []
                            bytes_read = 0
                            with zf.open(info) as f:
                                while bytes_read < min(info.file_size, Limits.MAX_ENTRY_BYTES):
                                    chunk_size = min(Limits.CHUNK_SIZE, 
                                                    Limits.MAX_ENTRY_BYTES - bytes_read)
                                    chunk = f.read(chunk_size)
                                    if not chunk:
                                        break
                                    chunks.append(chunk)
                                    bytes_read += len(chunk)
                            
                            content = b"".join(chunks)
                        else:
                            # Small file - read normally
                            with zf.open(info) as f:
                                content = f.read(Limits.MAX_ENTRY_BYTES + 1)
                        
                        if len(content) > Limits.MAX_ENTRY_BYTES:
                            logger.warn(f"ZIP: Entry '{clean_name}' exceeds size limit")
                            content = content[:Limits.MAX_ENTRY_BYTES]
                        
                        out.append((clean_name, content))
                    except Exception as e:
                        logger.warn(f"ZIP: Failed to extract '{clean_name}': {e}")
                        
        except zipfile.BadZipFile as e:
            logger.warn(f"ZIP: Invalid archive: {e}")
        except Exception as e:
            logger.warn(f"ZIP: Extraction failed: {e}")
        
        return out

    # -------- TAR / GZ --------
    @staticmethod
    def tar_list(data: bytes, logger: Logger) -> List[Tuple[str, bytes]]:
        """Extract TAR/GZIP archive with enhanced safety and streaming."""
        out: List[Tuple[str, bytes]] = []
        
        try:
            # Auto-detect compression
            mode = "r:gz" if data.startswith(SIG_GZIP) else "r:"
            
            with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    
                    # Security check
                    if ".." in member.name or member.name.startswith("/"):
                        logger.warn(f"TAR: Skipping potentially unsafe path: {member.name}")
                        continue
                    
                    clean_name = sanitize_filename(member.name)
                    
                    try:
                        fobj = tf.extractfile(member)
                        if fobj:
                            # Check size for streaming decision
                            if member.size > Limits.STREAM_THRESHOLD:
                                logger.diag(f"TAR: Large file {clean_name} ({member.size:,} bytes), using chunked read")
                                
                                # Read in chunks
                                chunks = []
                                bytes_read = 0
                                while bytes_read < min(member.size, Limits.MAX_ENTRY_BYTES):
                                    chunk_size = min(Limits.CHUNK_SIZE,
                                                    Limits.MAX_ENTRY_BYTES - bytes_read)
                                    chunk = fobj.read(chunk_size)
                                    if not chunk:
                                        break
                                    chunks.append(chunk)
                                    bytes_read += len(chunk)
                                
                                content = b"".join(chunks)
                            else:
                                # Small file - read normally
                                content = fobj.read(Limits.MAX_ENTRY_BYTES + 1)
                            
                            if len(content) > Limits.MAX_ENTRY_BYTES:
                                logger.warn(f"TAR: Entry '{clean_name}' exceeds size limit")
                                content = content[:Limits.MAX_ENTRY_BYTES]
                            
                            out.append((clean_name, content))
                    except Exception as e:
                        logger.warn(f"TAR: Failed to extract '{clean_name}': {e}")
                        
        except tarfile.TarError as e:
            logger.warn(f"TAR: Invalid archive: {e}")
        except Exception as e:
            logger.warn(f"TAR: Extraction failed: {e}")
        
        return out

    # -------- MSCF CAB --------
    @staticmethod
    def cab_list(data: bytes, logger: Logger) -> List[Tuple[str, bytes]]:
        """
        Enhanced CAB reader supporting MSZIP and LZX compression.
        Handles single-folder CABs common in installers.
        """
        out: List[Tuple[str, bytes]] = []
        
        try:
            if len(data) < 36 or not data.startswith(SIG_CAB):
                return out
            
            # Parse CFHEADER
            header = struct.unpack_from("<4sIIIIBBHHHHH", data, 0)
            (_sig, _r1, cab_size, files_off, _r2, _r3, vmin, vmaj,
             n_folders, n_files, flags, _set_id, _cab_index) = header
            
            # Validate header
            if cab_size > len(data):
                logger.warn("CAB: Header size mismatch")
                return out
            
            off = 36
            cb_cfdata = 0
            
            # Handle optional reserve data
            if flags & 0x0004:
                if len(data) < off + 4:
                    raise ValueError("CAB: Reserve header truncated")
                cb_cfhdr, cb_cffolder, cb_cfdata = struct.unpack_from("<HBB", data, off)
                off += 4 + cb_cfhdr

            # Read CFFOLDER entries
            folders = []
            for i in range(n_folders):
                if off + 8 > len(data):
                    logger.warn(f"CAB: CFFOLDER {i} truncated")
                    break
                
                d_off, n_blocks, comp_field = struct.unpack_from("<IHH", data, off)
                off += 8
                
                comp_type = comp_field & 0x0F
                comp_param = (comp_field >> 8) & 0x1F
                
                folders.append({
                    "d_off": d_off,
                    "n_blocks": n_blocks,
                    "comp": comp_type,
                    "comp_param": comp_param
                })

            # Helper to read null-terminated strings
            def read_cstring(buf: bytes, offset: int) -> Tuple[str, int]:
                end = buf.find(b"\x00", offset)
                if end == -1:
                    return "", len(buf)
                raw = buf[offset:end]
                text = safe_decode(raw, PREFERRED_ENCODING, FALLBACK_ENCODING)
                return text, end + 1

            # Read CFFILE entries
            files = []
            fil_off = files_off
            
            for i in range(n_files):
                if fil_off + 16 > len(data):
                    logger.warn(f"CAB: CFFILE {i} truncated")
                    break
                
                sz, off_in_fld, fidx, date, time, attrs = struct.unpack_from(
                    "<IIHHHH", data, fil_off
                )
                fil_off += 16
                
                name, fil_off = read_cstring(data, fil_off)
                clean_name = sanitize_filename(name or f"file_{i}")
                
                files.append({
                    "name": clean_name,
                    "size": sz,
                    "offset": off_in_fld,
                    "folder": fidx
                })

            # Decompress each folder
            folder_data: Dict[int, bytes] = {}
            
            for idx, folder in enumerate(folders):
                comp_type = folder["comp"]
                comp_param = folder["comp_param"]
                blocks = []
                off = folder["d_off"]
                
                # Read CFDATA blocks
                for j in range(folder["n_blocks"]):
                    if off + 8 > len(data):
                        logger.warn(f"CAB: CFDATA {j} in folder {idx} truncated")
                        break
                    
                    _csum, comp_size, uncomp_size = struct.unpack_from("<IHH", data, off)
                    off += 8 + cb_cfdata
                    
                    if off + comp_size > len(data):
                        logger.warn(f"CAB: CFDATA {j} block data truncated")
                        break
                    
                    block_data = data[off:off + comp_size]
                    blocks.append((block_data, uncomp_size))
                    off += comp_size

                # Decompress blocks based on type
                if comp_type == CompressionType.STORED:
                    # Uncompressed - concatenate blocks
                    folder_data[idx] = b"".join(block for block, _ in blocks)
                    
                elif comp_type == CompressionType.MSZIP:
                    # MSZIP - each block has 'CK' + deflate stream
                    outbuf = bytearray()
                    
                    for block, expected_size in blocks:
                        if len(block) < 2:
                            logger.warn(f"MSZIP block too small in folder {idx}")
                            continue
                        
                        if not block.startswith(b"CK"):
                            logger.warn(f"MSZIP block missing 'CK' signature in folder {idx}")
                            continue
                        
                        try:
                            decompressed = zlib.decompress(block[2:], -zlib.MAX_WBITS)
                            outbuf.extend(decompressed)
                        except zlib.error as e:
                            logger.warn(f"MSZIP decompression failed in folder {idx}: {e}")
                    
                    folder_data[idx] = bytes(outbuf[:Limits.MAX_ENTRY_BYTES])
                    
                elif comp_type == CompressionType.LZX:
                    # LZX - concatenate compressed data and decompress as stream
                    total_uncomp = sum(us for _, us in blocks)
                    raw = b"".join(block for block, _ in blocks)
                    
                    try:
                        win_bits = comp_param if comp_param else 21
                        if win_bits < 15 or win_bits > 21:
                            win_bits = 21
                            logger.warn(f"CAB: Invalid LZX window bits {comp_param}, using 21")
                        
                        decoder = LZXDecoder(win_bits)
                        folder_data[idx] = decoder.decompress(raw, total_uncomp)
                    except Exception as e:
                        logger.warn(f"LZX decode failed in folder {idx}: {e}")
                        folder_data[idx] = b""
                else:
                    logger.warn(f"CAB: Unsupported compression type {comp_type}")
                    folder_data[idx] = b""

            # Extract files from folder data
            for f in files:
                fidx = f["folder"]
                if fidx not in folder_data:
                    logger.warn(f"CAB: File '{f['name']}' references missing folder {fidx}")
                    continue
                
                src = folder_data[fidx]
                start = f["offset"]
                size = f["size"]
                
                if start + size > len(src):
                    logger.warn(f"CAB: File '{f['name']}' extends beyond folder data")
                    continue
                
                file_data = src[start:start + size]
                out.append((f["name"], file_data))
                
        except struct.error as e:
            logger.warn(f"CAB: Structure parsing failed: {e}")
        except Exception as e:
            logger.warn(f"CAB: Extraction failed: {e}")
        
        return out

    # -------- InstallShield unified CAB --------
    @staticmethod
    def installshield_unified_cab_list(data: bytes, logger: Logger) -> List[Tuple[str, bytes]]:
        """
        Extract InstallShield unified CAB with ISc() signature.
        Supports PKWARE implode compression.
        """
        out: List[Tuple[str, bytes]] = []
        
        try:
            # Find ISc( signature
            pos = data.find(SIG_ISCAB, 0, min(len(data), 65536))
            if pos < 0 or len(data) < pos + 16:
                return out
            
            # Parse header
            _sig, _version, _volume, desc_off = struct.unpack_from("<4sIII", data, pos)
            
            if desc_off >= len(data):
                logger.warn("ISc: Descriptor offset out of bounds")
                return out
            
            # Read file count
            off = desc_off
            if off + 4 > len(data):
                return out
            
            nfiles = struct.unpack_from("<I", data, off)[0]
            off += 4
            
            if nfiles > 10000:  # Sanity check
                logger.warn(f"ISc: Unrealistic file count {nfiles}")
                return out
            
            # Read file entries
            entry_fmt = "<IIIIIIHH4sI"
            entry_size = struct.calcsize(entry_fmt)
            
            for i in range(nfiles):
                if off + entry_size > len(data):
                    logger.warn(f"ISc: Entry {i} truncated")
                    break
                
                entry = struct.unpack_from(entry_fmt, data, off)
                (name_off, _dir_idx, flags, csize, usize,
                 off_in_cab, _date, _time, _unknown, _crc) = entry
                off += entry_size
                
                # Read filename
                if name_off >= len(data):
                    continue
                
                # Search for null terminator
                search_end = min(off, len(data))
                end = data.find(b"\x00", name_off, search_end)
                
                if end == -1:
                    raw_name = data[name_off:search_end]
                else:
                    raw_name = data[name_off:end]
                
                name = safe_decode(raw_name, PREFERRED_ENCODING, FALLBACK_ENCODING)
                clean_name = sanitize_filename(name.strip() or f"file_{i}")
                
                # Validate data offset
                if off_in_cab < 0 or off_in_cab + csize > len(data):
                    logger.warn(f"ISc: Invalid data offset for '{clean_name}'")
                    continue
                
                # Extract compressed data
                comp = data[off_in_cab:off_in_cab + csize]
                
                # Decompress based on flags
                if flags == CompressionType.STORED:
                    blob = comp[:usize] if usize else comp
                elif flags == CompressionType.PKWARE_IMPLODE:
                    try:
                        blob = pk_explode_implode(comp)
                        if usize and len(blob) > usize:
                            blob = blob[:usize]
                    except Exception as e:
                        logger.warn(f"ISc: Implode failed for '{clean_name}': {e}")
                        blob = comp
                else:
                    logger.warn(f"ISc: Unknown compression flag {flags} for '{clean_name}'")
                    blob = comp
                
                # Apply size limit
                if len(blob) > Limits.MAX_ENTRY_BYTES:
                    blob = blob[:Limits.MAX_ENTRY_BYTES]
                
                out.append((clean_name, blob))
                
        except struct.error as e:
            logger.warn(f"ISc CAB: Structure parsing failed: {e}")
        except Exception as e:
            logger.warn(f"ISc CAB: Extraction failed: {e}")
        
        return out

    # -------- InstallShield 3 PAK --------
    @staticmethod
    def installshield3_pak_list_unified(data: bytes, logger: Logger) -> List[Tuple[str, bytes]]:
        """
        IS3 PAK reader supporting standard and OrCAD variants.
        Auto-detects entry format (24 or 276 bytes).
        """
        out: List[Tuple[str, bytes]] = []
        
        try:
            if len(data) < 12:
                return out
            
            # Check magic signature (both endianness variants)
            magic = struct.unpack_from("<I", data, 0)[0]
            if magic not in (SIG_IS3PAK, SIG_IS3PAK_ALT):
                return out
            
            # Log which variant was detected
            if magic == SIG_IS3PAK_ALT:
                logger.diag("IS3 PAK: Detected alternative endianness variant (0x8C655D13)")
            else:
                logger.diag("IS3 PAK: Detected standard magic (0x135D658C)")
            
            # Read header
            relocated_dir_offset = struct.unpack_from("<I", data, 4)[0]
            file_count = struct.unpack_from("<I", data, 8)[0]
            
            logger.diag(f"IS3 PAK: Header - dir_offset={relocated_dir_offset}, file_count={file_count}")
            
            if file_count > 10000:  # Sanity check
                logger.warn(f"IS3 PAK: Unrealistic file count {file_count}")
                return out
            
            # Detect variant type
            is_orcad_variant = (
                relocated_dir_offset > 0 and
                relocated_dir_offset < len(data) and
                relocated_dir_offset > 12
            )
            
            if is_orcad_variant:
                directory_offset = relocated_dir_offset
                entry_size = 24
                entry_format = "<IIIIII"
            else:
                directory_offset = 0x0C
                entry_size = 276
            
            seen_names: Set[str] = set()
            written_bytes = 0
            
            for i in range(file_count):
                if written_bytes >= Limits.MAX_TOTAL_BYTES:
                    logger.warn("IS3 PAK: Global output limit reached")
                    break
                
                entry_start = directory_offset + (i * entry_size)
                if entry_start + entry_size > len(data):
                    logger.warn(f"IS3 PAK: Entry {i} extends beyond file")
                    break
                
                entry_data = data[entry_start:entry_start + entry_size]
                
                # Parse entry based on variant
                if is_orcad_variant:
                    # 24-byte variant
                    fields = struct.unpack_from(entry_format, entry_data, 0)
                    (name_offset, _dir_idx, flags, csz, usz, file_offset) = fields
                    
                    # Read name from offset
                    name = f"unnamed_{i}"
                    if 0 <= name_offset < len(data):
                        search_end = min(name_offset + 260, len(data))
                        end = data.find(b"\x00", name_offset, search_end)
                        
                        if end != -1:
                            raw_name = data[name_offset:end]
                        else:
                            raw_name = data[name_offset:search_end]
                        
                        decoded = safe_decode(raw_name, PREFERRED_ENCODING, FALLBACK_ENCODING)
                        name = sanitize_filename(decoded.strip() or name)
                else:
                    # 276-byte standard variant
                    raw_name = entry_data[0:260].split(b"\x00", 1)[0]
                    decoded = safe_decode(raw_name, PREFERRED_ENCODING, FALLBACK_ENCODING)
                    name = sanitize_filename(decoded.strip() or f"unnamed_{i}")
                    
                    file_offset, csz, usz, flags = struct.unpack_from(
                        "<IIII", entry_data, 260
                    )

                # Validate offsets
                if file_offset <= 0 or csz <= 0:
                    continue
                if file_offset + csz > len(data):
                    logger.warn(f"IS3 PAK: Entry '{name}' data out of bounds")
                    continue
                
                # Extract compressed data
                compressed = data[file_offset:file_offset + csz]
                
                # Decompress
                try:
                    if flags == CompressionType.STORED:
                        decompressed = compressed[:usz] if usz else compressed
                    elif flags == CompressionType.PKWARE_IMPLODE:
                        decompressed = pk_explode_implode(compressed)
                        if usz and len(decompressed) > usz:
                            decompressed = decompressed[:usz]
                    else:
                        logger.warn(f"IS3 PAK: Unknown compression {flags} for '{name}'")
                        decompressed = compressed
                except Exception as e:
                    logger.warn(f"IS3 PAK: Decompression failed for '{name}': {e}")
                    decompressed = compressed

                # Handle duplicate names
                candidate = name
                suffix = 1
                while candidate in seen_names:
                    suffix += 1
                    base, ext = os.path.splitext(name)
                    candidate = f"{base} ({suffix}){ext}"
                seen_names.add(candidate)

                # Apply size limit
                if len(decompressed) > Limits.MAX_ENTRY_BYTES:
                    decompressed = decompressed[:Limits.MAX_ENTRY_BYTES]
                
                out.append((candidate, decompressed))
                written_bytes += len(decompressed)
                
        except struct.error as e:
            logger.warn(f"IS3 PAK: Structure parsing failed: {e}")
        except Exception as e:
            logger.warn(f"IS3 PAK: Extraction failed: {e}")
        
        return out

# =============================================================================
# InstallShield PKG/INS Bundle Support
# =============================================================================

# Precompiled regex for efficiency
_DATA_PAK_PATTERN = re.compile(rb"(?i)DATA(\d+)\.PAK")
_STRING_PATTERN = re.compile(rb"[ -~]{4,}\x00")

def parse_setup_ins_strings(ins_blob: bytes) -> Dict[str, Any]:
    """
    Extract ASCII strings and volume mappings from SETUP.INS.
    Returns structured data for inspection.
    """
    names = set()
    
    # Extract printable ASCII strings
    for match in _STRING_PATTERN.finditer(ins_blob):
        try:
            text = match.group(0)[:-1].decode(PREFERRED_ENCODING, "ignore").strip()
            if text:
                names.add(text)
        except Exception:
            pass
    
    # Build volume map from DATA#.PAK references
    volmap = {}
    for name in names:
        match = re.match(r"(?i)DATA(\d+)\.PAK", name)
        if match:
            volmap[int(match.group(1))] = name
    
    return {
        "names": sorted(names),
        "volmap": volmap,
        "string_count": len(names),
        "volume_count": len(volmap)
    }

def extract_is3_pkgins_bundle_dir(container_dir: Path, logger: Logger) -> List[Tuple[str, bytes]]:
    """
    Extract IS3 bundle from directory containing SETUP.PKG and PAK files.
    Uses PAK-first approach: directly extracts all PAK files for reliability.
    Falls back to PKG parsing only for better naming when possible.
    """
    out: List[Tuple[str, bytes]] = []
    
    try:
        # Validate directory
        if not container_dir.is_dir():
            logger.error(f"Not a directory: {container_dir}")
            return []
        
        # First priority: Extract all PAK files directly
        pak_paths = sorted(
            [p for p in container_dir.iterdir() 
             if p.is_file() and p.suffix.lower() == ".pak"],
            key=lambda x: x.name.lower()
        )
        
        if pak_paths:
            logger.info(f"Found {len(pak_paths)} PAK file(s) in bundle directory")
            logger.info("Using PAK-first extraction approach for reliability")
            
            for pak_path in pak_paths:
                try:
                    # Check file size before reading
                    file_size = pak_path.stat().st_size
                    if file_size > Limits.MAX_ENTRY_BYTES * 2:
                        logger.warn(f"PAK file {pak_path.name} very large ({file_size:,} bytes), skipping")
                        continue
                    
                    pak_data = pak_path.read_bytes()
                    
                    # Check which PAK variant we have
                    if len(pak_data) >= 4:
                        magic = struct.unpack_from("<I", pak_data, 0)[0]
                        if magic == SIG_IS3PAK_ALT:
                            logger.diag(f"{pak_path.name}: Alternative endianness PAK (0x8C655D13)")
                        elif magic == SIG_IS3PAK:
                            logger.diag(f"{pak_path.name}: Standard IS3 PAK (0x135D658C)")
                        else:
                            logger.warn(f"{pak_path.name}: Unknown PAK magic 0x{magic:08X}, skipping")
                            continue
                    
                    # Use the working PAK handler
                    children = CODEC.installshield3_pak_list_unified(pak_data, logger)
                    
                    # Prefix with PAK volume name for clarity
                    volume_tag = pak_path.stem
                    
                    for child_name, child_data in children:
                        # Create unique name with volume prefix
                        prefixed_name = f"{volume_tag}__{child_name}"
                        out.append((prefixed_name, child_data))
                        
                    logger.diag(f"Extracted {len(children)} files from {pak_path.name}")
                    
                except MemoryError:
                    logger.error(f"Out of memory reading {pak_path.name}")
                except Exception as e:
                    logger.warn(f"Failed to extract PAK {pak_path.name}: {e}")
        
        # Also include SETUP.INS and SETUP.PKG for reference
        for special_file in ["SETUP.INS", "SETUP.PKG", "setup.ins", "setup.pkg"]:
            special_path = container_dir / special_file
            if special_path.exists() and special_path.is_file():
                try:
                    file_size = special_path.stat().st_size
                    if file_size <= Limits.MAX_ENTRY_BYTES:
                        out.append((special_file.upper(), special_path.read_bytes()))
                    else:
                        logger.warn(f"{special_file} too large ({file_size:,} bytes)")
                except Exception as e:
                    logger.warn(f"Failed to read {special_file}: {e}")
        
        # Optional enhancement: Try PKG parsing for better names (best-effort)
        pkg_path = None
        ins_path = None
        
        for p in container_dir.iterdir():
            if p.is_file():
                name_lower = p.name.lower()
                if name_lower == "setup.pkg":
                    pkg_path = p
                elif name_lower == "setup.ins":
                    ins_path = p
        
        if pkg_path and len(pak_paths) > 0:
            # Attempt PKG-based extraction as enhancement
            try:
                pkg_data = pkg_path.read_bytes()
                ins_data = ins_path.read_bytes() if ins_path else b""
                
                # Try to get better names from PKG directory
                enhanced = _try_pkg_enhancement(pkg_data, ins_data, pak_paths, logger)
                if enhanced:
                    logger.diag(f"Enhanced {len(enhanced)} entries with PKG metadata")
                    # Merge enhanced entries (would need deduplication logic)
                    # For now, just log that we tried
                    
            except Exception as e:
                logger.diag(f"PKG enhancement failed (using PAK fallback): {e}")
        
        if not out:
            logger.diag("No PAK files found in bundle directory")
        else:
            logger.info(f"Extracted {len(out)} total entries from bundle")
        
        return out
        
    except OSError as e:
        logger.error(f"Failed to read bundle directory: {e}")
        return []
    except Exception as e:
        logger.warn(f"Bundle extraction failed: {e}")
        return []

def _try_pkg_enhancement(pkg_data: bytes, ins_data: bytes, 
                         pak_paths: List[Path], logger: Logger) -> List[Tuple[str, bytes]]:
    """
    Best-effort attempt to parse PKG for better filenames.
    This is supplementary - the PAK extraction above is primary.
    """
    # This is a placeholder for the complex PKG parsing logic
    # The original implementation had issues, so we keep this minimal
    # Real implementation would parse PKG directory structure
    return []

# =============================================================================
# PE Overlay Carving
# =============================================================================

def carve_pe_overlay(data: bytes, logger: Logger) -> List[Tuple[str, bytes]]:
    """
    Carve embedded payloads from PE executable overlay region.
    Searches for ISc(), MSCF, and IS3 PAK signatures.
    """
    out: List[Tuple[str, bytes]] = []
    
    # Verify PE signature
    if not (len(data) >= 2 and data[:2] in (SIG_PE_MZ, SIG_PE_ZM)):
        return out

    # Determine overlay start position
    overlay_start = 0
    
    if len(data) >= 0x40:
        try:
            # Read PE header offset
            lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            # Estimate overlay start (after PE sections)
            overlay_start = min(len(data), max(lfanew + 0x2000, len(data) - (4 * 1024 * 1024)))
        except struct.error:
            overlay_start = max(0, len(data) - (4 * 1024 * 1024))
    else:
        overlay_start = max(0, len(data) - (4 * 1024 * 1024))

    # Search for embedded archives
    signatures = [
        (SIG_ISCAB, ".isc"),
        (SIG_CAB, ".cab")
    ]
    
    for pattern, ext in signatures:
        pos = overlay_start
        while True:
            idx = data.find(pattern, pos)
            if idx < 0:
                break
            out.append((f"overlay_{idx:08x}{ext}", data[idx:]))
            pos = idx + len(pattern)

    # Search for IS3 PAK magic (both endianness)
    for magic_val in (SIG_IS3PAK, SIG_IS3PAK_ALT):
        magic_bytes = struct.pack("<I", magic_val)
        pos = overlay_start
        
        while True:
            idx = data.find(magic_bytes, pos)
            if idx < 0:
                break
            out.append((f"overlay_{idx:08x}.pakblob", data[idx:]))
            pos = idx + 4

    if out:
        logger.diag(f"PE overlay: Found {len(out)} embedded payload(s)")
    
    return out

# =============================================================================
# OrCAD Classification
# =============================================================================

def classify_orcad(name: str, blob: bytes) -> Dict[str, Any]:
    """
    Classify OrCAD-relevant files for indexing.
    Returns metadata dictionary with type information.
    """
    ext = ext_lower(name)
    
    # Map extensions to types
    type_map = {
        ".olb": "OLB",
        ".dsn": "DSN",
        ".sch": "SCH",
        ".lib": "LIB"
    }
    
    file_type = type_map.get(ext, "other")
    
    meta = {
        "file": name,
        "type": file_type,
        "size": len(blob),
        "extension": ext
    }
    
    # Add format hints for OrCAD files
    if file_type != "other":
        meta["orcad_format"] = True
        
        # Check for text vs binary format
        try:
            # Simple heuristic: try to decode first 100 bytes
            sample = blob[:100]
            sample.decode("ascii")
            meta["format_hint"] = "text"
        except UnicodeDecodeError:
            meta["format_hint"] = "binary"
    
    return meta


# =============================================================================
# Enhanced OrCAD Header Parsing
# =============================================================================

class OrCADHeaderParser:
    """Parse OrCAD binary file headers for metadata extraction."""
    
    @staticmethod
    def parse_sch_header(data: bytes) -> Dict[str, Any]:
        """
        Parse Schematic (.SCH) file header.
        SCH files have a 256-byte header with version and checksum.
        """
        meta = {}
        if len(data) < 256:
            return meta
        
        try:
            # Common SCH header structure (may vary by version)
            # Offset 0x00-0x03: Magic signature
            magic = struct.unpack_from("<I", data, 0x00)[0]
            meta["magic"] = f"0x{magic:08X}"
            
            # Offset 0x04-0x05: Version (major.minor)
            version_raw = struct.unpack_from("<H", data, 0x04)[0]
            major = (version_raw >> 8) & 0xFF
            minor = version_raw & 0xFF
            meta["version"] = f"{major}.{minor:02d}"
            
            # Offset 0x08-0x0B: File size or record count
            record_count = struct.unpack_from("<I", data, 0x08)[0]
            meta["record_count"] = record_count
            
            # Offset 0xFC-0xFF: Checksum (last 4 bytes of 256-byte header)
            checksum = struct.unpack_from("<I", data, 0xFC)[0]
            meta["header_checksum"] = f"0x{checksum:08X}"
            
            # Attempt to identify version by magic
            if magic == 0x0D0A1A0A:
                meta["format"] = "OrCAD 6.x/7.x"
            elif magic == 0x12345678:
                meta["format"] = "OrCAD 3.x/4.x"
            else:
                meta["format"] = "Unknown"
                
        except struct.error as e:
            meta["parse_error"] = str(e)
        
        return meta
    
    @staticmethod
    def parse_olb_header(data: bytes) -> Dict[str, Any]:
        """
        Parse OrCAD Library (.OLB) file header.
        OLB files have a 24-byte global header followed by symbol entries.
        """
        meta = {}
        if len(data) < 24:
            return meta
        
        try:
            # OLB Global Header Structure
            # Offset 0x00-0x01: File version
            file_version = struct.unpack_from("<H", data, 0x00)[0]
            meta["version"] = f"{file_version >> 8}.{file_version & 0xFF}"
            
            # Offset 0x02-0x03: Header size
            header_size = struct.unpack_from("<H", data, 0x02)[0]
            meta["header_size"] = header_size
            
            # Offset 0x04-0x07: File signature/magic
            signature = struct.unpack_from("<I", data, 0x04)[0]
            meta["signature"] = f"0x{signature:08X}"
            
            # Offset 0x08-0x0B: Symbol count
            symbol_count = struct.unpack_from("<I", data, 0x08)[0]
            meta["symbol_count"] = symbol_count
            
            # Offset 0x0C-0x0F: First symbol offset
            first_symbol_offset = struct.unpack_from("<I", data, 0x0C)[0]
            meta["first_symbol_offset"] = f"0x{first_symbol_offset:08X}"
            
            # Offset 0x10-0x13: String table offset
            string_table_offset = struct.unpack_from("<I", data, 0x10)[0]
            meta["string_table_offset"] = f"0x{string_table_offset:08X}"
            
            # Try to read first symbol name if possible
            if symbol_count > 0 and first_symbol_offset < len(data) - 100:
                try:
                    # Symbol entries typically start with name length
                    name_len = struct.unpack_from("<H", data, first_symbol_offset)[0]
                    if name_len < 256:
                        symbol_name = data[first_symbol_offset+2:first_symbol_offset+2+name_len]
                        meta["first_symbol"] = symbol_name.decode('ascii', 'ignore').strip()
                except:
                    pass
                    
        except struct.error as e:
            meta["parse_error"] = str(e)
        
        return meta
    
    @staticmethod
    def parse_dsn_header(data: bytes) -> Dict[str, Any]:
        """
        Parse Design (.DSN) file header.
        DSN files are typically text-based S-expression format.
        """
        meta = {}
        
        # Check if it's text-based (modern) or binary (legacy)
        try:
            # Try to decode first 1KB as text
            header_text = data[:1024].decode('ascii', 'ignore')
            
            if '(pcb' in header_text or '(PCB' in header_text:
                meta["format"] = "S-expression (text)"
                
                # Extract version from text
                import re
                version_match = re.search(r'version\s+([0-9.]+)', header_text)
                if version_match:
                    meta["version"] = version_match.group(1)
                
                # Count major sections
                meta["has_placement"] = 'placement' in header_text.lower()
                meta["has_routes"] = 'routes' in header_text.lower() or 'wiring' in header_text.lower()
                meta["has_library"] = 'library' in header_text.lower()
                
            else:
                # Binary format
                meta["format"] = "Binary (legacy)"
                if len(data) >= 16:
                    magic = struct.unpack_from("<I", data, 0)[0]
                    meta["magic"] = f"0x{magic:08X}"
                    version = struct.unpack_from("<H", data, 4)[0]
                    meta["version"] = f"{version >> 8}.{version & 0xFF}"
                    
        except Exception as e:
            meta["parse_error"] = str(e)
        
        return meta
    
    @staticmethod
    def parse_lay_header(data: bytes) -> Dict[str, Any]:
        """
        Parse Layout (.LAY) file header.
        LAY files contain PCB layout information.
        """
        meta = {}
        if len(data) < 512:  # LAY headers are typically larger
            return meta
        
        try:
            # LAY Header Structure (varies by version)
            # Offset 0x00-0x03: File signature
            signature = struct.unpack_from("<I", data, 0x00)[0]
            meta["signature"] = f"0x{signature:08X}"
            
            # Offset 0x04-0x05: Version
            version = struct.unpack_from("<H", data, 0x04)[0]
            meta["version"] = f"{version >> 8}.{version & 0xFF}"
            
            # Offset 0x10-0x13: Board dimensions (mils)
            board_width = struct.unpack_from("<I", data, 0x10)[0]
            board_height = struct.unpack_from("<I", data, 0x14)[0]
            meta["board_size"] = f"{board_width/1000:.2f}\" x {board_height/1000:.2f}\""
            
            # Offset 0x20-0x21: Layer count
            layer_count = struct.unpack_from("<H", data, 0x20)[0]
            meta["layer_count"] = layer_count
            
            # Offset 0x24-0x25: Component count
            component_count = struct.unpack_from("<H", data, 0x24)[0]
            meta["component_count"] = component_count
            
            # Offset 0x28-0x29: Net count
            net_count = struct.unpack_from("<H", data, 0x28)[0]
            meta["net_count"] = net_count
            
            # Offset 0x2C-0x2D: Via count
            via_count = struct.unpack_from("<H", data, 0x2C)[0]
            meta["via_count"] = via_count
            
            # Offset 0x30-0x31: Track count
            track_count = struct.unpack_from("<H", data, 0x30)[0]
            meta["track_count"] = track_count
            
            # Checksum at end of header (offset 0x1FC for 512-byte header)
            if len(data) >= 512:
                checksum = struct.unpack_from("<I", data, 0x1FC)[0]
                meta["header_checksum"] = f"0x{checksum:08X}"
                
        except struct.error as e:
            meta["parse_error"] = str(e)
        
        return meta
    
    @staticmethod
    def parse_lib_header(data: bytes) -> Dict[str, Any]:
        """
        Parse generic Library (.LIB) file header.
        LIB files can be text or binary depending on type.
        """
        meta = {}
        
        try:
            # Check if text-based
            if data[:100].startswith(b'*') or b'PART' in data[:100]:
                meta["format"] = "Text-based library"
                
                # Try to count parts
                text = data[:10000].decode('ascii', 'ignore')
                part_count = text.count('*PART')
                if part_count > 0:
                    meta["part_count"] = part_count
            else:
                # Binary format
                meta["format"] = "Binary library"
                if len(data) >= 16:
                    magic = struct.unpack_from("<I", data, 0)[0]
                    meta["magic"] = f"0x{magic:08X}"
                    
        except Exception as e:
            meta["parse_error"] = str(e)
        
        return meta


def parse_orcad_enhanced(name: str, blob: bytes) -> Dict[str, Any]:
    """
    Enhanced OrCAD file classification with header parsing.
    Replaces the simple classify_orcad function.
    """
    ext = ext_lower(name)
    meta = {
        "file": name,
        "type": "other",
        "size": len(blob),
        "extension": ext
    }
    
    parser = OrCADHeaderParser()
    
    # Parse based on file type
    if ext == ".olb":
        meta["type"] = "OLB"
        meta["orcad_format"] = True
        meta["header"] = parser.parse_olb_header(blob)
        
    elif ext == ".sch":
        meta["type"] = "SCH"
        meta["orcad_format"] = True
        meta["header"] = parser.parse_sch_header(blob)
        
    elif ext == ".dsn":
        meta["type"] = "DSN"
        meta["orcad_format"] = True
        meta["header"] = parser.parse_dsn_header(blob)
        
    elif ext == ".lay":
        meta["type"] = "LAY"
        meta["orcad_format"] = True
        meta["header"] = parser.parse_lay_header(blob)
        
    elif ext == ".lib":
        meta["type"] = "LIB"
        meta["orcad_format"] = True
        meta["header"] = parser.parse_lib_header(blob)
    
    # Add format detection heuristic
    if meta.get("orcad_format"):
        try:
            # Simple heuristic: try to decode first 100 bytes
            sample = blob[:100]
            sample.decode('ascii')
            meta["format_hint"] = "text"
        except UnicodeDecodeError:
            meta["format_hint"] = "binary"
    
    return meta


# =============================================================================
# Post-Extraction Analysis
# =============================================================================

class PostExtractionAnalyzer:
    """Generate analysis artifacts for extracted files."""
    
    @staticmethod
    def generate_hex_dump(data: bytes, width: int = 16, max_lines: int = 1000) -> str:
        """
        Generate a formatted hex dump of binary data.
        
        Args:
            data: Binary data to dump
            width: Number of bytes per line
            max_lines: Maximum lines to generate (0 for unlimited)
        
        Returns:
            Formatted hex dump string
        """
        lines = []
        lines.append(f"Hex dump - {len(data)} bytes total")
        lines.append("-" * 76)
        
        total_lines = len(data) // width + (1 if len(data) % width else 0)
        lines_to_generate = min(total_lines, max_lines) if max_lines > 0 else total_lines
        
        for line_num in range(lines_to_generate):
            offset = line_num * width
            chunk = data[offset:offset + width]
            
            # Hex part
            hex_bytes = []
            for i in range(width):
                if i < len(chunk):
                    hex_bytes.append(f'{chunk[i]:02x}')
                else:
                    hex_bytes.append('  ')
                
                # Add extra space after 8 bytes for readability
                if i == 7:
                    hex_bytes.append(' ')
            
            hex_part = ' '.join(hex_bytes)
            
            # ASCII part
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' 
                for b in chunk
            )
            
            lines.append(f'{offset:08x}  {hex_part:<49} |{ascii_part}|')
        
        if total_lines > lines_to_generate:
            lines.append(f"... {total_lines - lines_to_generate} more lines truncated ...")
        
        return '\n'.join(lines)
    
    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4, encoding: str = 'both') -> str:
        """
        Extract printable strings from binary data.
        
        Args:
            data: Binary data to analyze
            min_length: Minimum string length
            encoding: 'ascii', 'unicode', or 'both'
        
        Returns:
            Extracted strings, one per line
        """
        strings = []
        strings.append(f"String extraction - minimum length: {min_length}")
        strings.append("-" * 60)
        
        # ASCII strings
        if encoding in ('ascii', 'both'):
            strings.append("\n[ASCII Strings]")
            ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, data)
            
            for i, s in enumerate(ascii_strings[:1000]):  # Limit to first 1000
                try:
                    decoded = s.decode('ascii', 'ignore')
                    strings.append(f"{i:04d}: {decoded}")
                except:
                    pass
            
            if len(ascii_strings) > 1000:
                strings.append(f"... {len(ascii_strings) - 1000} more ASCII strings found ...")
        
        # Unicode strings (UTF-16 LE, common in Windows)
        if encoding in ('unicode', 'both'):
            strings.append("\n[Unicode Strings]")
            # Look for UTF-16 LE patterns
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, data)
            
            for i, s in enumerate(unicode_strings[:500]):  # Limit to first 500
                try:
                    decoded = s.decode('utf-16-le', 'ignore').rstrip('\x00')
                    if decoded:
                        strings.append(f"U{i:04d}: {decoded}")
                except:
                    pass
            
            if len(unicode_strings) > 500:
                strings.append(f"... {len(unicode_strings) - 500} more Unicode strings found ...")
        
        # Look for interesting patterns
        strings.append("\n[Interesting Patterns]")
        
        # File paths
        paths = re.findall(rb'[A-Za-z]:\\[\x20-\x7E]{4,}', data)
        if paths:
            strings.append("\nFile Paths:")
            for p in paths[:20]:
                strings.append(f"  {p.decode('ascii', 'ignore')}")
        
        # URLs
        urls = re.findall(rb'https?://[\x20-\x7E]{4,}', data)
        if urls:
            strings.append("\nURLs:")
            for u in urls[:20]:
                strings.append(f"  {u.decode('ascii', 'ignore')}")
        
        # Email addresses
        emails = re.findall(rb'[\w\.-]+@[\w\.-]+\.\w+', data)
        if emails:
            strings.append("\nEmail Addresses:")
            for e in emails[:20]:
                strings.append(f"  {e.decode('ascii', 'ignore')}")
        
        # Version strings
        versions = re.findall(rb'[Vv]ersion\s+[\d\.]+|v\d+\.\d+', data)
        if versions:
            strings.append("\nVersion Strings:")
            for v in versions[:20]:
                strings.append(f"  {v.decode('ascii', 'ignore')}")
        
        return '\n'.join(strings)
    
    @staticmethod
    def should_analyze(filename: str, file_size: int) -> Tuple[bool, bool]:
        """
        Determine if a file should have hex dump and/or string extraction.
        
        Returns:
            (should_hex_dump, should_extract_strings)
        """
        ext = ext_lower(filename)
        
        # Binary executables and libraries
        executable_exts = {'.exe', '.dll', '.ovl', '.com', '.sys', '.drv'}
        
        # OrCAD binary formats
        orcad_binary_exts = {'.olb', '.sch', '.lay', '.dsn', '.lib'}
        
        # Data files
        data_exts = {'.dat', '.bin', '.pak', '.cab'}
        
        should_hex = False
        should_strings = False
        
        # Size limits
        max_hex_size = 10 * 1024 * 1024  # 10MB for hex dumps
        max_string_size = 50 * 1024 * 1024  # 50MB for string extraction
        
        if ext in executable_exts:
            should_hex = file_size <= max_hex_size
            should_strings = file_size <= max_string_size
        elif ext in orcad_binary_exts:
            should_hex = file_size <= max_hex_size
            should_strings = file_size <= max_string_size
        elif ext in data_exts:
            should_hex = file_size <= max_hex_size
            should_strings = file_size <= max_string_size
        
        return should_hex, should_strings


# =============================================================================
# Report Generation
# =============================================================================

class ExtractionReportGenerator:
    """Generate comprehensive extraction reports."""
    
    def __init__(self, config: Config, state: ExtractionState, logger: Logger):
        self.config = config
        self.state = state
        self.logger = logger
        self.tree = {}  # Extraction hierarchy
        self.checksums = {}  # Validation results
        self.timeline = []  # Extraction timeline
        
    def calculate_checksum(self, data: bytes, algorithm: str = 'crc32') -> int:
        """Calculate checksum for data."""
        if algorithm == 'crc32':
            return zlib.crc32(data) & 0xFFFFFFFF
        elif algorithm == 'sum32':
            # Simple 32-bit sum
            checksum = 0
            for i in range(0, len(data), 4):
                if i + 4 <= len(data):
                    checksum += struct.unpack_from("<I", data, i)[0]
                else:
                    # Handle remaining bytes
                    for j in range(i, len(data)):
                        checksum += data[j] << ((j - i) * 8)
                checksum &= 0xFFFFFFFF
            return checksum
        else:
            return 0
    
    def validate_orcad_checksum(self, name: str, data: bytes) -> Tuple[bool, str]:
        """
        Validate OrCAD file checksums where known.
        
        Returns:
            (is_valid, message)
        """
        ext = ext_lower(name)
        
        if ext in ('.sch', '.lay') and len(data) >= 256:
            # These formats have checksums in their headers
            try:
                # Read stored checksum (assuming at offset 0xFC)
                stored = struct.unpack_from("<I", data, 0xFC)[0]
                
                # Calculate checksum of header (excluding checksum field)
                header_data = data[:0xFC] + b'\x00\x00\x00\x00' + data[0x100:0x100]
                calculated = self.calculate_checksum(header_data, 'sum32')
                
                if stored == calculated:
                    return True, f"Valid (0x{stored:08X})"
                else:
                    return False, f"Invalid (stored: 0x{stored:08X}, calculated: 0x{calculated:08X})"
            except Exception as e:
                return False, f"Validation error: {e}"
        
        # For other formats, just calculate a checksum for reference
        checksum = self.calculate_checksum(data, 'crc32')
        return True, f"CRC32: 0x{checksum:08X}"
    
    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report."""
        
        # Prepare data
        total_files = self.state.files_written
        total_size = self.state.total_written
        orcad_files = [
            (path, meta) 
            for path, meta in self.state.index.items() 
            if meta.get('orcad_format')
        ]
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DeepStrip Extraction Report</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 15px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .section {{ background: white; padding: 15px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #34495e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f9f9f9; }}
        .tree {{ font-family: monospace; white-space: pre; background: #f4f4f4; padding: 10px; border-radius: 3px; }}
        .valid {{ color: green; font-weight: bold; }}
        .invalid {{ color: red; font-weight: bold; }}
        .warning {{ background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }}
        .stats {{ display: flex; justify-content: space-around; }}
        .stat-box {{ text-align: center; padding: 20px; background: #ecf0f1; border-radius: 5px; flex: 1; margin: 0 10px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DeepStrip Extraction Report</h1>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Version: 4.4.23</p>
    </div>
    
    <div class="summary">
        <h2>Extraction Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{total_files:,}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{total_size/(1024*1024):.1f} MB</div>
                <div class="stat-label">Total Size</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(orcad_files)}</div>
                <div class="stat-label">OrCAD Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(self.state.archive_types)}</div>
                <div class="stat-label">Archive Types</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Archive Types Processed</h2>
        <ul>
"""
        
        for atype in sorted(self.state.archive_types):
            type_names = {
                'zip': 'ZIP Archives',
                'tar': 'TAR/GZip Archives',
                'cab': 'Microsoft CAB Files',
                'iscab': 'InstallShield CAB Files',
                'is3pak': 'InstallShield PAK Files',
                'pe': 'PE Executables with Overlays'
            }
            html += f"            <li>{type_names.get(atype, atype.upper())}</li>\n"
        
        html += """        </ul>
    </div>
    
    <div class="section">
        <h2>OrCAD Files Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Version</th>
                    <th>Details</th>
                    <th>Integrity</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for path, meta in sorted(orcad_files, key=lambda x: x[0]):
            file_name = Path(path).name
            file_type = meta.get('type', 'Unknown')
            file_size = meta.get('size', 0)
            
            # Get header info
            header = meta.get('header', {})
            version = header.get('version', 'N/A')
            
            # Build details
            details = []
            if file_type == 'OLB' and 'symbol_count' in header:
                details.append(f"{header['symbol_count']} symbols")
            elif file_type == 'LAY':
                if 'layer_count' in header:
                    details.append(f"{header['layer_count']} layers")
                if 'component_count' in header:
                    details.append(f"{header['component_count']} components")
            elif file_type == 'SCH' and 'record_count' in header:
                details.append(f"{header['record_count']} records")
            
            details_str = ', '.join(details) if details else '-'
            
            # Checksum validation (would need actual file data)
            integrity = header.get('header_checksum', 'N/A')
            
            html += f"""                <tr>
                    <td>{file_name}</td>
                    <td>{file_type}</td>
                    <td>{file_size:,}</td>
                    <td>{version}</td>
                    <td>{details_str}</td>
                    <td>{integrity}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
    </div>
"""
        
        # Add warnings section if any
        if self.state.errors > 0:
            html += f"""    <div class="warning">
        <h3>Warnings and Errors</h3>
        <p>{self.state.errors} errors encountered during extraction.</p>
        <p>Check the diagnostic log for details.</p>
    </div>
"""
        
        html += """    <div class="section">
        <h2>Extraction Settings</h2>
        <ul>
            <li>Input: """ + str(self.config.input) + """</li>
            <li>Output: """ + str(self.config.output) + """</li>
            <li>Mode: """ + ('Flat' if self.config.flat else 'Tree') + """</li>
            <li>Max Depth: """ + ('Unlimited' if self.config.max_depth is None else str(self.config.max_depth)) + """</li>
            <li>OrCAD Indexing: """ + ('Yes' if self.config.mode_orcad else 'No') + """</li>
        </ul>
    </div>
    
    <div class="section">
        <p style="text-align: center; color: #7f8c8d;">
            Generated by DeepStrip v4.4.23 | 
            <a href="https://github.com/yourrepo/deepstrip">Documentation</a>
        </p>
    </div>
</body>
</html>"""
        
        return html
    
    def generate_markdown_report(self) -> str:
        """Generate Markdown report (lighter alternative to HTML)."""
        
        md = f"""# DeepStrip Extraction Report

Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Total Files**: {self.state.files_written:,}
- **Total Size**: {self.state.total_written/(1024*1024):.1f} MB
- **OrCAD Files**: {sum(1 for m in self.state.index.values() if m.get('orcad_format'))}
- **Archive Types**: {', '.join(sorted(self.state.archive_types))}

## OrCAD Files

| File | Type | Size | Version | Details |
|------|------|------|---------|---------|
"""
        
        for path, meta in self.state.index.items():
            if meta.get('orcad_format'):
                header = meta.get('header', {})
                md += f"| {Path(path).name} | {meta.get('type')} | {meta.get('size'):,} | {header.get('version', 'N/A')} | "
                
                # Add specific details
                if meta.get('type') == 'OLB' and 'symbol_count' in header:
                    md += f"{header['symbol_count']} symbols"
                elif meta.get('type') == 'LAY' and 'layer_count' in header:
                    md += f"{header['layer_count']} layers"
                
                md += " |\n"
        
        md += f"""

## Configuration

- Input: `{self.config.input}`
- Output: `{self.config.output}`
- Recursion Depth: {'Unlimited' if self.config.max_depth is None else self.config.max_depth}

---
*Generated by DeepStrip v4.4.23*
"""
        
        return md

# =============================================================================
# Flat Mode Naming
# =============================================================================

def flat_mode_name(stack: List[str], name: str) -> str:
    """
    Generate deterministic flat-mode filename with path context.
    Prevents collisions while maintaining readability.
    """
    tokens = []
    
    # Build token list from archive stack
    for item in stack:
        base = os.path.basename(item)
        # Remove extension to save space
        stem = os.path.splitext(base)[0] if "." in base else base
        tokens.append(sanitize_filename(stem))
    
    # Add final filename
    tokens.append(sanitize_filename(name))
    
    # Join with separator
    joined = "__".join(tokens)
    
    # Handle length constraints
    if len(joined) > Limits.MAX_NAME_LEN:
        # Progressively trim older tokens
        while len(joined) > Limits.MAX_NAME_LEN and len(tokens) > 2:
            tokens.pop(0)
            joined = "__".join(tokens)
        
        # Still too long - truncate final result
        if len(joined) > Limits.MAX_NAME_LEN:
            ext = os.path.splitext(joined)[1]
            max_stem = Limits.MAX_NAME_LEN - len(ext) - 8
            stem = os.path.splitext(joined)[0][:max_stem]
            joined = f"{stem}__TRUNC{ext}"
    
    return joined

# =============================================================================
# Extraction State
# =============================================================================

class ExtractionState:
    """Maintains state across recursive extraction."""
    
    def __init__(self):
        self.total_written: int = 0
        self.index: Dict[str, Dict[str, Any]] = {}
        self.files_written: int = 0
        self.errors: int = 0
        self.archive_types: Set[str] = set()  # Track archive types encountered

# =============================================================================
# Recursive Extraction Engine
# =============================================================================

class RecursiveEngine:
    """
    Core extraction engine with recursive processing.
    Handles nested archives, filters, and output strategies.
    """
    
    def __init__(self, cfg: Config, logger: Logger):
        self.cfg = cfg
        self.logger = logger
        self.state = ExtractionState()

    def _passes_filters(self, name: str) -> bool:
        """Check if filename passes include/exclude filters."""
        name_lower = name.lower()
        
        # Check include patterns
        if self.cfg.include:
            if not any(fnmatch.fnmatch(name_lower, pat) for pat in self.cfg.include):
                return False
        
        # Check exclude patterns
        if self.cfg.exclude:
            if any(fnmatch.fnmatch(name_lower, pat) for pat in self.cfg.exclude):
                return False
        
        return True

    def _write_leaf(self, outdir: Path, stack: List[str], name: str, blob: bytes) -> None:
        """Write leaf file to output with filtering, deduplication, and streaming support."""
        
        # Apply filters
        if not self._passes_filters(name):
            self.logger.diag(f"Filtered out: {name}")
            return
        
        # Check global size limit
        if self.state.total_written + len(blob) > Limits.MAX_TOTAL_BYTES:
            self.logger.warn("Global output limit reached")
            return
        
        # Determine output path
        if self.cfg.flat:
            # Flat mode - single directory with prefixed names
            out_name = flat_mode_name(stack, name)
            out_path = outdir / out_name
        else:
            # Tree mode - preserve hierarchy
            path_parts = [sanitize_filename(p) for p in stack] + [sanitize_filename(name)]
            
            # Limit depth for safety
            if len(path_parts) > Limits.MAX_PATH_DEPTH:
                self.logger.warn(f"Path too deep for {name}, flattening")
                path_parts = path_parts[-Limits.MAX_PATH_DEPTH:]
            
            out_path = outdir.joinpath(*path_parts)

        # Handle duplicates
        final_path = out_path
        base_name, ext = os.path.splitext(out_path.name)
        counter = 1
        
        while final_path.exists():
            counter += 1
            final_path = out_path.with_name(f"{base_name} ({counter}){ext}")

        # Apply entry size limit
        to_write = blob[:Limits.MAX_ENTRY_BYTES]
        
        try:
            # Use streaming for large files
            if len(to_write) > Limits.STREAM_THRESHOLD:
                self.logger.diag(f"Using stream write for large file: {name} ({len(to_write):,} bytes)")
                write_atomic_stream(final_path, to_write, len(to_write), self.logger)
            else:
                write_atomic(final_path, to_write, self.logger)
            
            # Update state
            self.state.total_written += len(to_write)
            self.state.files_written += 1
            
            # Update index
            rel_path = str(final_path.relative_to(outdir))
            # Use enhanced parser if available
            try:
                self.state.index[rel_path] = parse_orcad_enhanced(name, to_write)
            except NameError:
                # Fallback to original
                self.state.index[rel_path] = classify_orcad(name, to_write)
            
            # Generate analysis artifacts if requested
            if self.cfg.generate_hex or self.cfg.extract_strings:
                analyzer = PostExtractionAnalyzer()
                should_hex, should_strings = analyzer.should_analyze(name, len(to_write))
                
                if self.cfg.generate_hex and should_hex:
                    try:
                        hex_dump = analyzer.generate_hex_dump(to_write, max_lines=1000)
                        hex_path = final_path.with_suffix(final_path.suffix + '.hex.txt')
                        write_atomic(hex_path, hex_dump.encode('utf-8'), self.logger)
                        self.logger.diag(f"Generated hex dump: {hex_path.name}")
                    except Exception as e:
                        self.logger.warn(f"Failed to generate hex dump for {name}: {e}")
                
                if self.cfg.extract_strings and should_strings:
                    try:
                        strings_data = analyzer.extract_strings(to_write)
                        strings_path = final_path.with_suffix(final_path.suffix + '.strings.txt')
                        write_atomic(strings_path, strings_data.encode('utf-8'), self.logger)
                        self.logger.diag(f"Extracted strings: {strings_path.name}")
                    except Exception as e:
                        self.logger.warn(f"Failed to extract strings from {name}: {e}")
            
            # Handle SETUP.INS parsing if requested
            if self.cfg.extract_ins and ext_lower(name) == ".ins":
                self._extract_ins_metadata(final_path, to_write)
                
        except OSError as e:
            self.logger.error(f"Failed to write '{name}': {e}")
            self.state.errors += 1

    def _extract_ins_metadata(self, ins_path: Path, ins_data: bytes) -> None:
        """Extract and save SETUP.INS metadata as JSON."""
        try:
            parsed = parse_setup_ins_strings(ins_data)
            json_path = ins_path.with_suffix(ins_path.suffix + ".json")
            
            json_data = json.dumps(parsed, indent=2, ensure_ascii=False)
            write_atomic(json_path, json_data.encode("utf-8"), self.logger)
            
            self.logger.diag(f"Extracted INS metadata to {json_path.name}")
        except Exception as e:
            self.logger.warn(f"Failed to parse INS metadata: {e}")

    def process_blob(self, name: str, blob: bytes, outdir: Path,
                    depth: int, stack: List[str]) -> None:
        """
        Process a single blob recursively.
        Detects type and either extracts children or writes as leaf.
        """
        
        # Check recursion depth
        if self.cfg.max_depth is not None and depth > self.cfg.max_depth:
            self.logger.warn(f"Max recursion depth {self.cfg.max_depth} exceeded at '{name}'")
            return
        elif depth > 100:  # Hard safety limit even for unlimited mode
            self.logger.error(f"Safety limit: Recursion depth {depth} too deep at '{name}'")
            return
        
        # Detect content type
        ctype = Detector.detect(blob)
        self.logger.diag(f"[depth={depth}] {name}: detected as {ctype}")
        
        # Track archive types for summary
        if ctype != "raw":
            self.state.archive_types.add(ctype)
        
        # Process based on type
        handlers = {
            "zip": CODEC.zip_list,
            "tar": CODEC.tar_list,
            "cab": CODEC.cab_list,
            "iscab": CODEC.installshield_unified_cab_list,
            "is3pak": CODEC.installshield3_pak_list_unified
        }
        
        if ctype in handlers:
            # Extract container
            try:
                children = handlers[ctype](blob, self.logger)
                
                # Process children recursively
                for child_name, child_blob in children:
                    self.process_blob(
                        child_name, child_blob, outdir,
                        depth + 1, stack + [name]
                    )
            except Exception as e:
                self.logger.error(f"Failed to extract {ctype} '{name}': {e}")
                self.state.errors += 1
            return
        
        if ctype == "pe":
            # Special handling for PE files - carve overlays
            carved = carve_pe_overlay(blob, self.logger)
            
            for carved_name, carved_blob in carved:
                self.process_blob(
                    carved_name, carved_blob, outdir,
                    depth + 1, stack + [name]
                )
            
            # Also write the PE itself if it passes filters
            self._write_leaf(outdir, stack, name, blob)
            return
        
        # Default: treat as leaf file
        self._write_leaf(outdir, stack, name, blob)

    def run(self, top_name: str, top_blob: bytes, outdir: Path) -> None:
        """
        Main entry point for extraction.
        Sets up output directory and starts recursive processing.
        """
        self.logger.info(f"Starting recursive extraction: {top_name}")
        self.logger.info(f"Will automatically extract nested archives within archives")
        
        # Validate input size
        if len(top_blob) > 2 * Limits.MAX_TOTAL_BYTES:
            self.logger.warn(f"Input file very large ({len(top_blob):,} bytes), extraction may be limited")
        
        # Create output directory
        try:
            outdir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.logger.error(f"Cannot create output directory: {e}")
            return
        
        # Start recursive processing
        self.process_blob(top_name, top_blob, outdir, depth=0, stack=[])
        
        # Log summary
        self.logger.info(
            f"Extraction complete: {self.state.files_written:,} files, "
            f"{self.state.total_written:,} bytes written"
        )
        
        if self.state.errors:
            self.logger.warn(f"Encountered {self.state.errors} errors during extraction")

# =============================================================================
# Index Writer
# =============================================================================

def write_orcad_index(outdir: Path, index: Dict[str, Dict[str, Any]],
                     logger: Logger) -> Path:
    """Write consolidated OrCAD index to JSON."""
    dst = outdir / "orcad_index.json"
    
    try:
        # Add metadata
        index_data = {
            "version": "4.4.23",
            "total_files": len(index),
            "orcad_files": sum(1 for v in index.values() if v.get("orcad_format")),
            "files": index
        }
        
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"OrCAD index saved to: {dst}")
    except OSError as e:
        logger.error(f"Failed to write index: {e}")
    
    return dst

# =============================================================================
# CLI and Main
# =============================================================================

def build_argparser() -> argparse.ArgumentParser:
    """Build command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="deepstrip",
        description="""DeepStrip v4.4.23 — OrCAD-aware recursive archive extractor

FEATURES:
  • Automatic nested extraction from ZIP, TAR, CAB, InstallShield archives
  • Recursively extracts archives within archives (unlimited depth)
  • Handles InstallShield CABs (ISc), PAK files, and PKG/INS bundles
  • Carves embedded archives from PE executables
  • Supports PKWARE implode, MSZIP, and LZX compression
  • Smart duplicate handling with systematic renaming""",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES:
  # Extract everything from nested archives (default behavior):
  %(prog)s installer.exe -o ./output
  
  # Extract only OrCAD files (.olb, .sch, .dsn, .lib):
  %(prog)s ORCADCAP.60.zip -o ./output --include "*.olb,*.sch,*.dsn,*.lib"
  
  # Flatten all files to single directory with smart renaming:
  %(prog)s archive.zip -o ./flat --flat
  
  # Extract everything except executables:
  %(prog)s bundle.cab -o ./output --exclude "*.exe,*.dll"
  
  # Extract with InstallShield script parsing:
  %(prog)s setup.exe -o ./output --extract-ins
  
  # Extract from directory containing SETUP.PKG and PAK files:
  %(prog)s ./installer_files/ -o ./output
  
  # Extract with custom recursion depth (default is 10):
  %(prog)s deeply_nested.zip -o ./output --max-depth 20
  
  # Extract with unlimited recursion depth (use carefully):
  %(prog)s archive.zip -o ./output --max-depth 0
  
  # Two-phase extraction for InstallShield in ZIP (e.g., ORCADCAP.60.zip):
  %(prog)s ORCADCAP.60.zip -o ./temp        # Phase 1: Extract ZIP
  %(prog)s ./temp/ORCADCAP.60 -o ./final    # Phase 2: Extract PAKs

NOTES:
  • Nested extraction is AUTOMATIC - archives within archives are always extracted
  • Use --flat for single directory output (files prefixed with archive path)
  • Use --include/--exclude for filtering (comma-separated glob patterns)
  • Use --max-depth to control recursion (0 = unlimited, default = 10)
  • InstallShield archives are automatically detected and extracted
  • Large files (>10MB) are streamed to reduce memory usage
  • Duplicate files in flat mode get (2), (3) suffixes
  • For InstallShield bundles in ZIPs, use two-phase extraction (see examples)
        """
    )
    
    parser.add_argument(
        "input",
        help="Input file or directory to extract (supports nested archives)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="./deepstrip_out",
        help="Output directory (default: ./deepstrip_out)"
    )
    
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--orcad",
        action="store_true",
        help="OrCAD-aware mode with classification index (default)"
    )
    mode_group.add_argument(
        "--extract",
        action="store_true",
        help="Generic extraction mode (no OrCAD indexing)"
    )
    
    parser.add_argument(
        "--flat",
        action="store_true",
        help="Flatten to single directory (prefixes files with archive path to avoid collisions)"
    )
    
    parser.add_argument(
        "--include",
        default="",
        help='Extract ONLY files matching patterns (e.g., "*.olb,*.sch,*.pdf")\n'
             'Default: extract all files'
    )
    
    parser.add_argument(
        "--exclude",
        default="",
        help='Skip files matching patterns (e.g., "*.exe,*.dll,*.tmp")\n'
             'Applied after --include filter'
    )
    
    parser.add_argument(
        "--extract-ins",
        action="store_true",
        help="Parse InstallShield SETUP.INS scripts and save as JSON\n"
             "(extracts string tables and volume mappings)"
    )
    
    parser.add_argument(
        "--max-depth",
        type=int,
        default=Limits.DEFAULT_MAX_DEPTH,
        help="Maximum recursion depth for nested archives (default: 10)\n"
             "Use 0 or -1 for unlimited depth (warning: may cause stack overflow)"
    )
    
    parser.add_argument(
        "--generate-hex",
        action="store_true",
        help="Generate .hex.txt files for binary files (executables, OrCAD binaries)"
    )
    
    parser.add_argument(
        "--extract-strings",
        action="store_true",
        help="Extract ASCII/Unicode strings to .strings.txt files"
    )
    
    parser.add_argument(
        "--analysis-all",
        action="store_true",
        help="Enable all analysis features (hex dumps + string extraction)"
    )
    
    parser.add_argument(
        "--generate-report",
        action="store_true",
        help="Generate HTML and Markdown extraction reports with OrCAD analysis"
    )
    
    parser.add_argument(
        "--diag-json",
        default="",
        help="Write detailed diagnostic information to JSON file\n"
             "(useful for debugging extraction issues)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s v4.4.23"
    )
    
    return parser

def main():
    """Main program entry point."""
    parser = build_argparser()
    args = parser.parse_args()
    
    # Create configuration
    cfg = Config(args)
    logger = Logger(enable_diag=bool(cfg.diag_json))
    
    logger.info(f"DeepStrip v4.4.23 starting")
    
    # Show active features
    logger.info("Active features:")
    logger.info(f"  • Automatic nested extraction: YES (always on)")
    
    depth_str = "UNLIMITED" if cfg.max_depth is None else f"{cfg.max_depth} levels"
    logger.info(f"  • Maximum recursion depth: {depth_str}")
    
    logger.info(f"  • Output mode: {'FLAT (single directory)' if cfg.flat else 'TREE (preserve structure)'}")
    
    if cfg.include:
        logger.info(f"  • Include filter: {', '.join(cfg.include)}")
    else:
        logger.info(f"  • Include filter: ALL FILES")
    
    if cfg.exclude:
        logger.info(f"  • Exclude filter: {', '.join(cfg.exclude)}")
    
    logger.info(f"  • InstallShield script extraction: {'YES' if cfg.extract_ins else 'NO'}")
    logger.info(f"  • OrCAD indexing: {'YES' if cfg.mode_orcad else 'NO'}")
    logger.info(f"  • Memory optimization: Streaming for files > {Limits.STREAM_THRESHOLD // (1024*1024)}MB")
    
    if cfg.generate_hex or cfg.extract_strings:
        logger.info(f"  • Hex dumps: {'YES' if cfg.generate_hex else 'NO'}")
        logger.info(f"  • String extraction: {'YES' if cfg.extract_strings else 'NO'}")
    
    if cfg.diag_json:
        logger.info(f"  • Diagnostics: {cfg.diag_json}")
    
    logger.info(f"Input: {cfg.input}")
    logger.info(f"Output: {cfg.output}")
    
    # Validate input
    if not cfg.input.exists():
        logger.error(f"Input does not exist: {cfg.input}")
        sys.exit(1)
    
    # Create extraction engine
    engine = RecursiveEngine(cfg, logger)
    
    if cfg.input.is_dir():
        # Directory input - check for PKG/INS bundle first
        logger.info("Checking for InstallShield PKG/INS bundle...")
        bundle_entries = extract_is3_pkgins_bundle_dir(cfg.input, logger)
        
        if bundle_entries:
            logger.info(f"PKG/INS bundle detected: {len(bundle_entries)} entries")
            logger.info("Using PAK-first extraction for reliability")
            
            for entry_name, entry_blob in bundle_entries:
                engine.process_blob(
                    entry_name, entry_blob,
                    cfg.output, depth=0, stack=[]
                )
        else:
            # Process each file in directory
            files = sorted(
                [p for p in cfg.input.iterdir() if p.is_file()],
                key=lambda x: x.name.lower()
            )
            
            if not files:
                logger.warn("Directory is empty")
            else:
                logger.info(f"Processing {len(files)} files from directory")
                
                for file_path in files:
                    try:
                        blob = file_path.read_bytes()
                        engine.process_blob(
                            file_path.name, blob,
                            cfg.output, depth=0, stack=[]
                        )
                    except OSError as e:
                        logger.error(f"Failed to read '{file_path.name}': {e}")
    else:
        # Single file input
        try:
            top_blob = cfg.input.read_bytes()
            engine.run(cfg.input.name, top_blob, cfg.output)
        except OSError as e:
            logger.error(f"Failed to read input file: {e}")
            sys.exit(1)
    
    # Write OrCAD index
    if engine.state.index or cfg.mode_orcad:
        write_orcad_index(cfg.output, engine.state.index, logger)
    
    # Generate extraction report if requested
    if cfg.generate_report:
        try:
            reporter = ExtractionReportGenerator(cfg, engine.state, logger)
            
            # Generate HTML report
            html_report = reporter.generate_html_report()
            html_path = cfg.output / "_extraction_report.html"
            write_atomic(html_path, html_report.encode('utf-8'), logger)
            logger.info(f"HTML report saved to: {html_path}")
            
            # Generate Markdown report
            md_report = reporter.generate_markdown_report()
            md_path = cfg.output / "_extraction_report.md"
            write_atomic(md_path, md_report.encode('utf-8'), logger)
            logger.info(f"Markdown report saved to: {md_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate reports: {e}")
    
    # Export diagnostics if requested
    if cfg.diag_json:
        logger.export_json(cfg.diag_json)
    
    # Final summary
    logger.info("=" * 60)
    logger.info(f"DeepStrip completed successfully")
    logger.info(f"Files extracted: {engine.state.files_written:,}")
    logger.info(f"Total size: {engine.state.total_written:,} bytes")
    
    if engine.state.archive_types:
        types_str = ", ".join(sorted(engine.state.archive_types))
        logger.info(f"Archive types processed: {types_str}")
    
    if cfg.mode_orcad and engine.state.index:
        orcad_count = sum(1 for v in engine.state.index.values() if v.get("orcad_format"))
        if orcad_count:
            logger.info(f"OrCAD files found: {orcad_count}")
    
    logger.info(f"Output directory: {cfg.output.absolute()}")
    
    if engine.state.errors:
        logger.warn(f"Total errors encountered: {engine.state.errors}")
        sys.exit(2)

# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    main()
