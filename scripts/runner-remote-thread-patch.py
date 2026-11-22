#!/usr/bin/env python3
"""Build a GE-Proton runner whose CreateRemoteThreadEx does not push the caller's activation context
onto the new thread's TEB.

Why: wine's kernelbase CreateRemoteThreadEx, after NtCreateThreadEx succeeds, calls
RtlActivateActivationContextEx(0, teb, actctx, &cookie) whenever the calling thread has an active
activation context. `teb` is the new thread's TEB address. When the thread was created in another
process, that address belongs to the other process, but RtlActivateActivationContextEx reads and
writes it in the caller's address space. A .NET or WinForms injector (which usually runs with an
activation context active) then crashes or corrupts its own state while injecting a DLL by remote
thread.

The change: the `jz` that skips the activate/release pair when there is no context becomes a short
`jmp` straight to the release call. The reference taken by RtlGetActiveActivationContext is still
dropped (RtlReleaseActivationContext(NULL) is a no-op), and the activation is skipped for every new
thread. Side effect: threads created in the same process no longer inherit the creator's active
activation context.

How the site is found: CreateRemoteThreadEx is located through the PE export table, its extent through
the .pdata entry that starts at that address, and the site by a byte signature whose relocated and
frame-relative operands are wildcards. The signature must match exactly once inside the function, its
three RIP-relative calls must go through the ntdll import slots for NtCreateThreadEx,
RtlActivateActivationContextEx and RtlReleaseActivationContext, and the branch must be the expected
`74 1a`. Anything else stops the script before any output is left behind.

Usage (python3 stdlib only):
    python3 -I scripts/runner-remote-thread-patch.py --input GE-Proton11-12.tar.gz \
        --sha256 <tarball sha256> --output out/GE-Proton11-12-rt [--repack out/GE-Proton11-12-rt.tar.gz]
    python3 -I scripts/runner-remote-thread-patch.py --input <extracted runner dir> \
        --sha256 <sha256 of its stock x86_64 kernelbase.dll> --output ...
    python3 -I scripts/runner-remote-thread-patch.py --self-test
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import struct
import sys
import tarfile
import tempfile
from pathlib import Path

# The 64-bit kernelbase.dll and the prefix template's copy of it (a relative symlink in GE-Proton
# releases, a separate file in some builds). The 32-bit copies are left alone.
KERNELBASE_PATHS = (
    "files/lib/wine/x86_64-windows/kernelbase.dll",
    "files/share/default_pfx/drive_c/windows/system32/kernelbase.dll",
)

TARGET_EXPORT = b"CreateRemoteThreadEx"

# (bytes, None for a wildcard). Wildcards cover IAT displacements, the frame offsets of locals and the
# failure branch target, which all move between builds.
W = None
SIGNATURE: tuple[int | None, ...] = (
    0xFF, 0x15, W, W, W, W,              # call [rip+NtCreateThreadEx]
    0x85, 0xC0,                          # test eax, eax
    0x0F, 0x85, W, W, W, W,              # jnz  <failure path>
    0x4C, 0x8B, 0x45, W,                 # mov  r8, [rbp+actctx]
    0x4D, 0x85, 0xC0,                    # test r8, r8
    0x74, 0x1A,                          # jz   <after release>        <- patched
    0x31, 0xC9,                          # xor  ecx, ecx
    0x48, 0x8B, 0x55, W,                 # mov  rdx, [rbp+teb]
    0x4C, 0x8D, 0x4D, W,                 # lea  r9, [rbp+cookie]
    0xFF, 0x15, W, W, W, W,              # call [rip+RtlActivateActivationContextEx]
    0x48, 0x8B, 0x4D, W,                 # mov  rcx, [rbp+actctx]
    0xFF, 0x15, W, W, W, W,              # call [rip+RtlReleaseActivationContext]
)
# Offsets within SIGNATURE.
CALL_CREATE = 0
LOAD_ACTCTX_DISP = 17
BRANCH = 21
CALL_ACTIVATE = 33
RELEASE_LOAD = 39
RELEASE_ACTCTX_DISP = 42
CALL_RELEASE = 43
EXPECT = bytes((0x74, 0x1A))
# jmp short to the `mov rcx, [rbp+actctx]` that feeds the release call.
WRITE = bytes((0xEB, RELEASE_LOAD - (BRANCH + 2)))
EXPECTED_IMPORTS = {
    CALL_CREATE: "NtCreateThreadEx",
    CALL_ACTIVATE: "RtlActivateActivationContextEx",
    CALL_RELEASE: "RtlReleaseActivationContext",
}


class PatchError(Exception):
    """Any input that is not exactly what the patch was derived from."""


# --------------------------------------------------------------------------------------------------
# PE reading (PE32+ only)


class Pe:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PatchError("not a PE file (no MZ header)")
        lfanew = self.u32(0x3C)
        if self.read(lfanew, 4) != b"PE\0\0":
            raise PatchError("not a PE file (no PE signature)")
        coff = lfanew + 4
        machine, nsections = struct.unpack_from("<HH", data, self.bounds(coff, 20))
        opt_size = self.u16(coff + 16)
        if machine != 0x8664:
            raise PatchError(f"not an x86-64 image (machine {machine:#x})")
        opt = coff + 20
        if self.u16(opt) != 0x20B:
            raise PatchError("not a PE32+ optional header")
        ndirs = self.u32(opt + 108)
        self.dirs = []
        for i in range(min(ndirs, 16)):
            self.dirs.append(struct.unpack_from("<II", data, self.bounds(opt + 112 + 8 * i, 8)))
        self.sections = []
        sec = opt + opt_size
        for i in range(nsections):
            raw = self.read(sec + 40 * i, 40)
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", raw, 8)
            chars = struct.unpack_from("<I", raw, 36)[0]
            self.sections.append((raw[:8].rstrip(b"\0"), va, max(vsize, rsize), rsize, rptr, chars))

    def bounds(self, off: int, n: int) -> int:
        if off < 0 or n < 0 or off + n > len(self.data):
            raise PatchError(f"read past end of file at {off:#x}")
        return off

    def read(self, off: int, n: int) -> bytes:
        return self.data[self.bounds(off, n) : off + n]

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, self.bounds(off, 2))[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, self.bounds(off, 4))[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, self.bounds(off, 8))[0]

    def section_of(self, rva: int):
        for s in self.sections:
            if s[1] <= rva < s[1] + s[2]:
                return s
        raise PatchError(f"RVA {rva:#x} is in no section")

    def off(self, rva: int, n: int = 1) -> int:
        _, va, _, rsize, rptr, _ = self.section_of(rva)
        if rva + n > va + rsize:
            raise PatchError(f"RVA {rva:#x} has no file backing")
        return self.bounds(rptr + (rva - va), n)

    def cstr(self, rva: int, limit: int = 256) -> bytes:
        start = self.off(rva)
        end = self.data.find(b"\0", start, start + limit)
        if end < 0:
            raise PatchError(f"unterminated string at RVA {rva:#x}")
        return self.data[start:end]

    def directory(self, index: int) -> tuple[int, int]:
        if index >= len(self.dirs) or self.dirs[index][0] == 0:
            raise PatchError(f"data directory {index} is absent")
        return self.dirs[index]

    def export_rva(self, name: bytes) -> int:
        erva, esize = self.directory(0)
        e = self.off(erva, 40)
        nfuncs, nnames, funcs, names, ords = struct.unpack_from("<IIIII", self.data, e + 20)
        hits = []
        for i in range(nnames):
            if self.cstr(self.u32(self.off(names + 4 * i, 4))) == name:
                ordinal = self.u16(self.off(ords + 2 * i, 2))
                if ordinal >= nfuncs:
                    raise PatchError("export ordinal out of range")
                hits.append(self.u32(self.off(funcs + 4 * ordinal, 4)))
        if len(hits) != 1:
            raise PatchError(f"export {name.decode()} found {len(hits)} times, expected once")
        rva = hits[0]
        if erva <= rva < erva + esize:
            raise PatchError(f"export {name.decode()} is a forwarder, not code")
        if not self.section_of(rva)[5] & 0x20000000:
            raise PatchError(f"export {name.decode()} is not in an executable section")
        return rva

    def function_end(self, begin: int) -> int:
        prva, psize = self.directory(3)
        hits = []
        for i in range(psize // 12):
            b, e, _ = struct.unpack_from("<III", self.data, self.off(prva + 12 * i, 12))
            if b == begin:
                hits.append(e)
        if len(hits) != 1 or hits[0] <= begin:
            raise PatchError(f"no single .pdata entry starts at {begin:#x}")
        return hits[0]

    def imports(self) -> dict[int, tuple[str, str]]:
        """IAT slot RVA -> (dll, symbol) for imports by name."""
        irva, _ = self.directory(1)
        slots: dict[int, tuple[str, str]] = {}
        for i in range(4096):
            d = self.off(irva + 20 * i, 20)
            oft, _, _, name, ft = struct.unpack_from("<IIIII", self.data, d)
            if oft == 0 and name == 0 and ft == 0:
                return slots
            dll = self.cstr(name).decode("ascii", "replace").lower()
            lookup = oft or ft
            for j in range(65536):
                entry = self.u64(self.off(lookup + 8 * j, 8))
                if entry == 0:
                    break
                if not entry >> 63:
                    sym = self.cstr((entry & 0x7FFFFFFF) + 2).decode("ascii", "replace")
                    slots[ft + 8 * j] = (dll, sym)
        raise PatchError("import directory has no terminator")


# --------------------------------------------------------------------------------------------------
# Locating and patching


def find_signature(blob: bytes, start: int, end: int) -> list[int]:
    n = len(SIGNATURE)
    first = SIGNATURE[0]
    hits = []
    i = blob.find(bytes((first,)), start, end)
    while 0 <= i <= end - n:
        if all(s is None or blob[i + k] == s for k, s in enumerate(SIGNATURE)):
            hits.append(i)
        i = blob.find(bytes((first,)), i + 1, end)
    return hits


def patch_kernelbase(data: bytes) -> tuple[bytes, dict]:
    """Return the patched image and a provenance record, or raise PatchError."""
    pe = Pe(data)
    begin = pe.export_rva(TARGET_EXPORT)
    end = pe.function_end(begin)
    fstart = pe.off(begin, end - begin)
    hits = find_signature(data, fstart, fstart + (end - begin))
    if len(hits) != 1:
        raise PatchError(
            f"signature matched {len(hits)} times inside CreateRemoteThreadEx "
            f"(RVA {begin:#x}..{end:#x}), expected exactly once"
        )
    site = hits[0]
    rva_of = lambda off: begin + (off - fstart)  # noqa: E731 (function lies in one section)

    if data[site + LOAD_ACTCTX_DISP] != data[site + RELEASE_ACTCTX_DISP]:
        raise PatchError("the tested and the released activation context are different locals")
    slots = pe.imports()
    for at, want in EXPECTED_IMPORTS.items():
        disp = struct.unpack_from("<i", data, site + at + 2)[0]
        slot = rva_of(site + at) + 6 + disp
        got = slots.get(slot)
        if got != ("ntdll.dll", want):
            raise PatchError(
                f"call at RVA {rva_of(site + at):#x} goes through {got or 'no named import'}, "
                f"expected ntdll.dll!{want}"
            )
    branch = site + BRANCH
    found = data[branch : branch + 2]
    if found != EXPECT:
        raise PatchError(f"bytes at the branch are {found.hex(' ')}, expected {EXPECT.hex(' ')}")
    out = bytearray(data)
    out[branch : branch + 2] = WRITE
    return bytes(out), {
        "function_rva": begin,
        "site_rva": rva_of(branch),
        "site_offset": branch,
        "expect": EXPECT.hex(" "),
        "write": WRITE.hex(" "),
    }


# --------------------------------------------------------------------------------------------------
# Runner trees


def sha256_fileobj(f) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    with open(path, "rb") as f:
        return sha256_fileobj(f)


def kernelbase_targets(root: Path) -> list[Path]:
    """The distinct regular files behind KERNELBASE_PATHS, each confined to `root`."""
    real_root = root.resolve()
    targets: list[Path] = []
    for rel in KERNELBASE_PATHS:
        p = root / rel
        if not p.exists():
            raise PatchError(f"{rel} is missing")
        real = p.resolve()
        if real_root not in real.parents:
            raise PatchError(f"{rel} resolves outside the runner tree")
        if not real.is_file():
            raise PatchError(f"{rel} is not a regular file")
        if real not in targets:
            targets.append(real)
    if len(targets) == 2 and targets[0].read_bytes() != targets[1].read_bytes():
        raise PatchError("the two kernelbase.dll copies differ")
    return targets


def safe_extract(fileobj, dest: Path) -> Path:
    """Extract into `dest`, which must end up holding exactly one top-level directory."""
    with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
        tops = set()
        for m in tf:
            name = m.name.removeprefix("./")
            if not name or name.startswith("/") or ".." in Path(name).parts:
                raise PatchError(f"archive member with unsafe path: {m.name!r}")
            if not (m.isfile() or m.isdir() or m.issym()):
                raise PatchError(f"archive member of unexpected type: {m.name!r}")
            tops.add(Path(name).parts[0])
        if len(tops) != 1:
            raise PatchError(f"archive has {len(tops)} top-level entries, expected one directory")
        tf.extractall(dest, filter="data")
        # The "data" filter adds owner write to files and tarfile leaves symlink mtimes at "now";
        # put both back as the archive has them so a repack reproduces upstream metadata. Group and
        # other write bits stay stripped: a runner has no business shipping world-writable files.
        for m in tf.getmembers():
            path = dest / m.name
            if m.issym():
                os.utime(path, ns=(m.mtime * 10**9,) * 2, follow_symlinks=False)
            elif m.isfile():
                os.chmod(path, m.mode & 0o755)
    top = dest / tops.pop()
    if not top.is_dir() or top.is_symlink():
        raise PatchError("archive's top-level entry is not a directory")
    return top


def repack(root: Path, out: Path, top: str) -> None:
    """Deterministic tar.gz: sorted entries, root ownership, original mtimes, gzip mtime 0."""
    with open(out, "xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, compresslevel=6) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:

            def norm(ti: tarfile.TarInfo) -> tarfile.TarInfo:
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                return ti

            def walk(path: Path, arc: str) -> None:
                tf.add(path, arcname=arc, recursive=False, filter=norm)
                if path.is_dir() and not path.is_symlink():
                    for child in sorted(path.iterdir(), key=lambda c: c.name):
                        walk(child, f"{arc}/{child.name}")

            walk(root, top)


def build(args: argparse.Namespace) -> int:
    src = Path(args.input)
    out = Path(args.output)
    repack_to = Path(args.repack) if args.repack else None
    expected = args.sha256.lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise PatchError("--sha256 must be 64 hex digits")
    if out.exists() or out.is_symlink():
        raise PatchError(f"output {out} already exists; refusing to overwrite")
    if repack_to and (repack_to.exists() or repack_to.is_symlink()):
        raise PatchError(f"repack target {repack_to} already exists; refusing to overwrite")
    if not out.parent.is_dir():
        raise PatchError(f"output parent {out.parent} does not exist")
    real_src = src.resolve()
    real_out_parent = out.parent.resolve()
    if src.is_dir() and (real_out_parent == real_src or real_src in real_out_parent.parents):
        raise PatchError("output must not be inside the source runner")

    work = Path(tempfile.mkdtemp(prefix=f".{out.name}.partial-", dir=out.parent))
    try:
        if src.is_file():
            # Hash and extract through one open file so the bytes extracted are the bytes verified.
            with open(src, "rb") as f:
                got = sha256_fileobj(f)
                if got != expected:
                    raise PatchError(f"input sha256 is {got}, expected {expected}")
                f.seek(0)
                tree = safe_extract(f, work)
        elif src.is_dir():
            stock = kernelbase_targets(src)
            got = sha256_file(stock[0])
            if got != expected:
                raise PatchError(f"stock kernelbase.dll sha256 is {got}, expected {expected}")
            tree = work / src.name
            shutil.copytree(src, tree, symlinks=True)
        else:
            raise PatchError(f"input {src} is neither a file nor a directory")

        targets = kernelbase_targets(tree)
        stock_bytes = targets[0].read_bytes()
        if src.is_dir() and hashlib.sha256(stock_bytes).hexdigest() != expected:
            raise PatchError("kernelbase.dll changed while the runner was being copied")
        patched, info = patch_kernelbase(stock_bytes)
        for t in targets:
            parent = t.parent.stat()
            st = t.stat()
            tmp = t.with_name(t.name + ".new")
            with open(tmp, "xb") as f:
                f.write(patched)
            os.chmod(tmp, st.st_mode & 0o7777)
            os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
            os.replace(tmp, t)
            os.utime(t.parent, ns=(parent.st_atime_ns, parent.st_mtime_ns))

        report = [
            f"input            {src} (sha256 {got}, verified)",
            f"function         CreateRemoteThreadEx at RVA {info['function_rva']:#x}",
            f"site             RVA {info['site_rva']:#x}, file offset {info['site_offset']:#x}: "
            f"{info['expect']} -> {info['write']}",
            f"stock sha256     {hashlib.sha256(stock_bytes).hexdigest()}",
        ]
        for rel in KERNELBASE_PATHS:
            report.append(f"patched sha256   {sha256_file(tree / rel)}  {rel}")

        os.rename(tree, out)
        if repack_to:
            try:
                repack(out, repack_to, args.name or out.name)
            except BaseException:
                repack_to.unlink(missing_ok=True)
                shutil.rmtree(out, ignore_errors=True)
                raise
            report.append(f"tarball sha256   {sha256_file(repack_to)}  {repack_to}")
        report.append(f"output           {out}")
        print("\n".join(report))
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------------------------------
# Offline self-test on a synthetic PE


def _synthetic_pe(body: bytes, *, imports: dict[str, int] | None = None, export_twice: bool = False) -> bytes:
    """A minimal PE32+ with .text (the function), .rdata (exports, imports, IAT) and .pdata.
    File alignment 0x200, section alignment 0x1000, so RVA and file offset differ."""
    text_rva, rdata_rva, pdata_rva = 0x1000, 0x2000, 0x3000
    func_rva = text_rva + 0x10
    names = list(imports or EXPECTED_IMPORTS.values())

    # .rdata: IAT, hint/name table, import descriptor, dll name, export directory.
    rd = bytearray(0x800)
    iat_off, hn_off, desc_off, dll_off, exp_off = 0x000, 0x100, 0x300, 0x340, 0x400
    hn = hn_off
    iat_rvas = {}
    for i, sym in enumerate(names):
        struct.pack_into("<Q", rd, iat_off + 8 * i, rdata_rva + hn)
        struct.pack_into("<H", rd, hn, 0)
        rd[hn + 2 : hn + 2 + len(sym)] = sym.encode()
        iat_rvas[sym] = rdata_rva + iat_off + 8 * i
        hn += 2 + len(sym) + 1 + ((len(sym) + 1) & 1)
    rd[dll_off : dll_off + 10] = b"ntdll.dll\0"
    struct.pack_into("<IIIII", rd, desc_off, 0, 0, 0, rdata_rva + dll_off, rdata_rva + iat_off)
    nexp = 2 if export_twice else 1
    funcs, nmtab, ords, nm = exp_off + 40, exp_off + 48, exp_off + 56, exp_off + 64
    struct.pack_into("<IIIII", rd, exp_off + 20, nexp, nexp, rdata_rva + funcs, rdata_rva + nmtab, rdata_rva + ords)
    for i in range(nexp):
        struct.pack_into("<I", rd, funcs + 4 * i, func_rva)
        struct.pack_into("<I", rd, nmtab + 4 * i, rdata_rva + nm)
        struct.pack_into("<H", rd, ords + 2 * i, i)
    rd[nm : nm + len(TARGET_EXPORT) + 1] = TARGET_EXPORT + b"\0"

    # .text: padding, then the function body with call displacements fixed up to the IAT slots.
    tx = bytearray(0x10) + bytearray(body)
    tx += bytes(0x400 - len(tx))
    pd = bytearray(0x200)
    struct.pack_into("<III", pd, 0, func_rva, func_rva + len(body), 0)

    hdr = bytearray(0x400)
    hdr[:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664, 3, 0, 0, 0, 240, 0x2022)
    opt = 0x98
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<I", hdr, opt + 108, 16)
    struct.pack_into("<II", hdr, opt + 112, rdata_rva + exp_off, 0x100)       # export
    struct.pack_into("<II", hdr, opt + 120, rdata_rva + desc_off, 40)         # import
    struct.pack_into("<II", hdr, opt + 136, pdata_rva, 12)                    # exception
    sec = opt + 240
    layout = [(b".text", text_rva, tx, 0x60000020), (b".rdata", rdata_rva, rd, 0x40000040),
              (b".pdata", pdata_rva, pd, 0x40000040)]
    raw = 0x400
    image = bytearray(hdr)
    for i, (name, va, blob, chars) in enumerate(layout):
        s = sec + 40 * i
        hdr_bytes = name.ljust(8, b"\0") + struct.pack("<IIII", len(blob), va, len(blob), raw)
        hdr_bytes += bytes(12) + struct.pack("<I", chars)
        image[s : s + 40] = hdr_bytes
        raw += len(blob)
    for _, _, blob, _ in layout:
        image += blob

    return bytes(image), iat_rvas, func_rva


def _fill_site(sig_at: int, iat_rvas: dict[str, int], func_rva: int, symbols: dict[int, str]) -> bytes:
    """The signature with concrete operands, as it would sit at body offset `sig_at`."""
    b = bytearray(s if s is not None else 0x20 for s in SIGNATURE)
    for at, sym in symbols.items():
        rip = func_rva + sig_at + at + 6
        struct.pack_into("<i", b, at + 2, iat_rvas[sym] - rip)
    b[LOAD_ACTCTX_DISP] = b[RELEASE_ACTCTX_DISP] = 0xE0
    return bytes(b)


def _make(sites: list[int], *, body_len: int = 0x120, symbols=None, edit=None, **kw) -> bytes:
    symbols = symbols or EXPECTED_IMPORTS
    body = bytearray(b"\xcc" * body_len)
    # First pass to learn the IAT layout (it does not depend on the body).
    _, iat_rvas, func_rva = _synthetic_pe(bytes(body), **kw)
    for at in sites:
        body[at : at + len(SIGNATURE)] = _fill_site(at, iat_rvas, func_rva, symbols)
    if edit:
        edit(body)
    image, _, _ = _synthetic_pe(bytes(body), **kw)
    return image


def self_test() -> int:
    failures = []
    layout_ok = (
        all(SIGNATURE[at : at + 2] == (0xFF, 0x15) for at in EXPECTED_IMPORTS)
        and tuple(SIGNATURE[BRANCH : BRANCH + 2]) == tuple(EXPECT)
        and SIGNATURE[RELEASE_LOAD : RELEASE_LOAD + 3] == (0x48, 0x8B, 0x4D)
        and SIGNATURE[LOAD_ACTCTX_DISP] is None and SIGNATURE[RELEASE_ACTCTX_DISP] is None
        and WRITE == bytes((0xEB, 0x10))
    )
    if not layout_ok:
        failures.append("signature offsets do not line up with the signature bytes")

    def expect_ok(label, image):
        try:
            out, info = patch_kernelbase(image)
        except PatchError as e:
            failures.append(f"{label}: unexpected failure: {e}")
            return
        diff = [i for i in range(len(image)) if image[i] != out[i]]
        if diff != [info["site_offset"], info["site_offset"] + 1] or out[diff[0] : diff[0] + 2] != WRITE:
            failures.append(f"{label}: wrong bytes changed: {diff}")
        try:
            patch_kernelbase(out)
            failures.append(f"{label}: patching twice did not fail")
        except PatchError:
            pass

    def expect_fail(label, image, needle):
        try:
            patch_kernelbase(image)
            failures.append(f"{label}: did not fail")
        except PatchError as e:
            if needle not in str(e):
                failures.append(f"{label}: failed for the wrong reason: {e}")

    expect_ok("one site", _make([0x40]))
    expect_fail("no site", _make([]), "matched 0 times")
    expect_fail("two sites", _make([0x10, 0x80]), "matched 2 times")
    expect_fail("site outside the function", _make_outside(), "matched 0 times")
    swapped = {CALL_CREATE: "NtCreateThreadEx", CALL_ACTIVATE: "RtlReleaseActivationContext",
               CALL_RELEASE: "RtlReleaseActivationContext"}
    expect_fail("wrong import", _make([0x40], symbols=swapped), "expected ntdll.dll!RtlActivateActivationContextEx")

    def other_local(body):
        body[0x40 + RELEASE_ACTCTX_DISP] = 0xD8
    expect_fail("different locals", _make([0x40], edit=other_local), "different locals")
    expect_fail("duplicate export", _make([0x40], export_twice=True), "found 2 times")
    expect_fail("not a PE", b"\0" * 0x400, "no MZ")
    good = _make([0x40])
    expect_fail("truncated", good[:0x500], "")

    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"self-test: {'ok' if not failures else f'{len(failures)} failure(s)'}")
    return 1 if failures else 0


def _make_outside() -> bytes:
    """A valid site placed in .text just past the function's .pdata extent."""
    body = bytearray(b"\xcc" * 0x40)
    image, iat_rvas, func_rva = _synthetic_pe(bytes(body))
    pe = Pe(image)
    at = len(body)  # first byte after the function
    site = _fill_site(at, iat_rvas, func_rva, EXPECTED_IMPORTS)
    off = pe.off(func_rva + at, len(site))
    return image[:off] + site + image[off + len(site) :]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--input", help="upstream runner tarball, or an extracted runner directory")
    ap.add_argument("--sha256", help="expected sha256 of the tarball, or of a directory's stock x86_64 kernelbase.dll")
    ap.add_argument("--output", help="directory to create for the patched runner (must not exist)")
    ap.add_argument("--repack", help="also write the patched runner as this .tar.gz (must not exist)")
    ap.add_argument("--name", help="top-level directory name inside the repacked tarball (default: output name)")
    ap.add_argument("--self-test", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not (args.input and args.sha256 and args.output):
        ap.error("--input, --sha256 and --output are required")
    try:
        return build(args)
    except (PatchError, OSError, tarfile.TarError, EOFError) as e:
        print(f"error: {e}; no output written", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
