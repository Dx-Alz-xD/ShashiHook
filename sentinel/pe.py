"""What a Windows executable looks like from the outside.

There is a trained PE classifier in this repository that reaches 0.9998
ROC-AUC, and it is not used. The audit is worth stating because the number is
seductive and the reason it is worthless is not obvious from the metrics:

    legitimate samples:  memtest.exe, ose.exe, setup.exe, DW20.EXE
    malicious samples:   VirusShare_4a400b747afe..., VirusShare_9bd57c82...

The two classes come from entirely different collection processes -- a Windows
installation on one side, a malware dump on the other -- so every strong
feature turns out to separate the COLLECTIONS rather than the behaviour.
SizeOfStackReserve sits at 0x100000 for 94% of the malicious set and 0x40000
for 65% of the legitimate one, which is a linker default. ExportNb is 0 for 99%
of malicious samples, which says they are EXEs and the legitimate set contains
DLLs. ImageBase is 0x400000 for 99% against 12%, which is 32-bit versus 64-bit.

Dropping all nineteen era and toolchain fields moves held-out AUC from 0.9998
to 0.9997 -- not because the rest is sound, but because the contamination is
everywhere. A model trained on this learns "did this come from VirusShare",
which is unknowable for a file arriving by email tomorrow. So it stays unwired.

What survives is entropy, because entropy is physics rather than provenance.
Compressed or encrypted bytes approach 8 bits per byte no matter who collected
them, and packing a binary is a deliberate act that hides its contents from
inspection. That is reported here as a percentile against the legitimate
population, stated as what it is -- a comparison against ordinary Windows
program files -- rather than as a probability of being malware.

Percentiles are honest in a way a score is not. "Higher entropy than 99.4% of
ordinary Windows binaries" invites a person to think; "0.87 malicious" invites
them to stop.
"""
from __future__ import annotations

import json
import math
import struct
from dataclasses import dataclass, field

from .config import ARTIFACTS

PERCENTILE_PATH = ARTIFACTS / "pe_entropy_percentiles.json"

# Entropy at which a section is compressed, encrypted or packed rather than
# ordinary code. Native x86 sits around 6.0-6.5; above 7.2 the bytes carry
# close to maximum information, which machine code does not.
PACKED_ENTROPY = 7.2


def shannon(data: bytes) -> float:
    """Bits of information per byte, 0 to 8."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    out = 0.0
    for c in counts:
        if c:
            p = c / n
            out -= p * math.log2(p)
    return out


@dataclass
class Section:
    name: str = ""
    raw_size: int = 0
    virtual_size: int = 0
    entropy: float = 0.0

    @property
    def packed(self) -> bool:
        return self.entropy >= PACKED_ENTROPY


@dataclass
class PEHeader:
    """Enough of a PE to describe it, parsed without a dependency."""
    ok: bool = False
    is_pe: bool = False
    machine: str = ""
    is_64bit: bool = False
    is_dll: bool = False
    sections: list[Section] = field(default_factory=list)
    n_sections: int = 0
    max_entropy: float = 0.0
    mean_entropy: float = 0.0
    error: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "is_pe": self.is_pe, "machine": self.machine,
            "is_64bit": self.is_64bit, "is_dll": self.is_dll,
            "n_sections": self.n_sections,
            "max_entropy": round(self.max_entropy, 3),
            "mean_entropy": round(self.mean_entropy, 3),
            "sections": [{"name": s.name, "raw_size": s.raw_size,
                          "entropy": round(s.entropy, 3), "packed": s.packed}
                         for s in self.sections],
            "notes": self.notes, "error": self.error,
        }


MACHINES = {0x014c: "x86", 0x8664: "x86-64", 0x01c0: "ARM", 0xaa64: "ARM64",
            0x0200: "Itanium", 0x01c4: "ARMv7"}


def parse(data: bytes) -> PEHeader:
    """Read the PE headers and measure each section's entropy.

    Hand-rolled rather than pulled from `pefile`, because the only things
    needed are the section table and the bytes each section covers. A parser
    this small cannot be tricked into executing anything, and it fails closed:
    any malformed field returns `ok=False` with a reason instead of raising
    into the analyser.
    """
    h = PEHeader()
    try:
        if len(data) < 64 or data[:2] != b"MZ":
            h.error = "not a DOS/PE image"
            return h
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
            h.error = "no PE signature"
            return h
        h.is_pe = True
        machine, n_sec, _, _, _, opt_size, chars = struct.unpack_from(
            "<HHIIIHH", data, pe_off + 4)
        h.machine = MACHINES.get(machine, f"0x{machine:04x}")
        h.is_dll = bool(chars & 0x2000)
        h.n_sections = n_sec

        opt_off = pe_off + 24
        if opt_off + 2 <= len(data):
            magic = struct.unpack_from("<H", data, opt_off)[0]
            h.is_64bit = magic == 0x20B

        sec_off = opt_off + opt_size
        # 96 is the documented ceiling for a sane image; more than that is a
        # malformed or deliberately confusing file, not something to trust.
        for i in range(min(n_sec, 96)):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            raw = data[off:off + 8]
            name = raw.split(b"\0")[0].decode("latin-1", "replace")
            vsize, _vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
            body = data[raddr:raddr + rsize] if rsize and raddr < len(data) else b""
            h.sections.append(Section(name=name, raw_size=rsize,
                                      virtual_size=vsize, entropy=shannon(body)))
        ents = [s.entropy for s in h.sections if s.raw_size > 0]
        if ents:
            h.max_entropy = max(ents)
            h.mean_entropy = sum(ents) / len(ents)
        h.ok = True

        packed = [s for s in h.sections if s.packed and s.raw_size > 512]
        if packed:
            h.notes.append(
                f"{len(packed)} section(s) at or above {PACKED_ENTROPY} bits per "
                f"byte ({', '.join(s.name for s in packed)}) -- the contents are "
                f"compressed or encrypted, so nothing can inspect them without "
                f"running the file")
        # A virtual size far beyond what is stored on disk is how a packer
        # reserves room to unpack itself into.
        for s in h.sections:
            if s.raw_size and s.virtual_size > s.raw_size * 4 and s.virtual_size > 0x10000:
                h.notes.append(
                    f"section {s.name} reserves {s.virtual_size:,} bytes in memory "
                    f"but stores only {s.raw_size:,} on disk -- room to unpack into")
                break
        return h
    except Exception as e:
        h.error = f"{type(e).__name__}: {e}"
        return h


# --------------------------------------------------------------- percentiles
_PCT: dict | None = None


def percentiles() -> dict:
    global _PCT
    if _PCT is None:
        try:
            _PCT = json.loads(PERCENTILE_PATH.read_text())
        except Exception:
            _PCT = {}
    return _PCT


def rank(value: float, field_name: str = "max_entropy") -> tuple[float, str]:
    """Where this file sits against ordinary Windows program files.

    Returns the percentile and a sentence. The reference population is stated
    in the sentence on purpose: it is a set of legitimate Windows binaries, not
    "all software", and a reader deserves to know what the comparison is.
    """
    table = percentiles().get(field_name, {})
    grid = table.get("legitimate")
    if not grid:
        return 0.0, ""
    pts = sorted((float(k), v) for k, v in grid.items())
    pct = 0.0
    for p, v in pts:
        if value >= v:
            pct = p
    pop = "legitimate Windows program files"
    if pct >= 99.0:
        sentence = (f"section entropy {value:.2f}, higher than {pct:g}% of {pop} "
                    f"— the contents are compressed or encrypted")
    elif pct >= 50.0:
        sentence = f"section entropy {value:.2f}, higher than {pct:g}% of {pop}"
    else:
        sentence = (f"section entropy {value:.2f}, unremarkable for {pop} "
                    f"— the bytes look like ordinary code")
    return pct, sentence
