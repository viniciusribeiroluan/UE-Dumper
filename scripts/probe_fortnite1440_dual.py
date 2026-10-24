"""Read-only Fortnite 14.40 comparison of two UNVERIFIED layout profiles.
Usage: Fortnite1440_DualProfileProbe.exe > resultado_perfis.txt 2>&1
Self-test: Fortnite1440_DualProfileProbe.exe --self-test
"""
import argparse
import ctypes
from ctypes import wintypes as w
import os
import struct
import sys

EXE = "FortniteClient-Win64-Shipping.exe"
PROFILES = {
    "A_1430_reference": dict(gworld=0x92B3420, gi=0x180, lp=0x38, pc=0x30,
                             pawn=0x2A0, camera=0x2B8, level=0x30,
                             actor_array=None, actor_count=None),
    "B_1440_unverified": dict(gworld=0x917BF08, gi=0x1A8, lp=0x38, pc=0x30,
                              pawn=0x310, camera=0x328, level=0x30,
                              actor_array=0x98, actor_count=0xA0),
}

def ptr(x):
    return x is not None and 0x10000 <= x < 0x800000000000 and x % 8 == 0

class Reader:
    def __init__(self, read, base):
        self.read = read
        self.base = base
        self.read_count = 0

    def get(self, addr, n):
        if not ptr(addr) or not 0 < n <= 4096:
            return None
        self.read_count += 1
        b = self.read(addr, n)
        return b if b is not None and len(b) == n else None

    def q(self, addr):
        b = self.get(addr, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def arr(self, addr, limit):
        b = self.get(addr, 16)
        if not b:
            return None
        data, count, capacity = struct.unpack("<Qii", b)
        if count < 0 or capacity < count or capacity > limit:
            return None
        if count and not ptr(data):
            return None
        return data, count

    def check(self, rva, p):
        world = self.q(self.base + rva)
        if not ptr(world):
            return None
        level = self.q(world + p["level"])
        gi = self.q(world + p["gi"])
        if not ptr(level) or not ptr(gi) or gi == level:
            return None
        if not ptr(self.q(level)) or not ptr(self.q(gi)):
            return None
        players = self.arr(gi + p["lp"], 16)
        if players is None or not 1 <= players[1] <= 4:
            return None
        local = self.q(players[0])
        if not ptr(local):
            return None
        controller = self.q(local + p["pc"])
        if not ptr(controller) or not ptr(self.q(controller)):
            return None
        score, evidence = 7, ["Level", "GameInstance", "LocalPlayers", "PlayerController"]
        for key, label in [("pawn", "Pawn"), ("camera", "Camera")]:
            candidate = self.q(controller + p[key])
            if ptr(candidate) and ptr(self.q(candidate)):
                score += 2
                evidence.append(label)
        if p["actor_array"] is not None:
            array = self.q(level + p["actor_array"])
            raw = self.get(level + p["actor_count"], 4)
            if raw:
                count = struct.unpack("<i", raw)[0]
                if 0 <= count <= 200000 and (count == 0 or ptr(array)):
                    score += 1
                    evidence.append("Actors")
        return score, world, evidence

    def scan(self, sections, p, limit):
        slots = []
        for rva, data in sections:
            for pos in range(0, len(data) - 7, 8):
                value = struct.unpack_from("<Q", data, pos)[0]
                if ptr(value):
                    slots.append(rva + pos)
        slots.sort(key=lambda x: (abs(x - p["gworld"]) > 0x200000,
                                  abs(x - p["gworld"]), x))
        hits = []
        for rva in slots[:limit]:
            match = self.check(rva, p)
            if match:
                hits.append((rva, *match))
        hits.sort(key=lambda x: (-x[1], abs(x[0] - p["gworld"])))
        return hits, min(limit, len(slots)), len(slots) > limit

class WinProcess:
    def __init__(self, pid):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.k
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenProcess.restype = w.HANDLE
        k.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k.ReadProcessMemory.restype = w.BOOL
        k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        k.CreateToolhelp32Snapshot.restype = w.HANDLE
        k.Module32FirstW.argtypes = [w.HANDLE, ctypes.c_void_p]
        k.Module32FirstW.restype = w.BOOL
        k.Module32NextW.argtypes = [w.HANDLE, ctypes.c_void_p]
        k.Module32NextW.restype = w.BOOL
        k.CloseHandle.argtypes = [w.HANDLE]
        self.handle = k.OpenProcess(0x0410, False, pid)
        if not self.handle:
            raise OSError("OpenProcess failed, Windows error %d" % ctypes.get_last_error())
        self.pid = pid
        class Module(ctypes.Structure):
            _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
                        ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
                        ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.c_void_p),
                        ("modBaseSize", w.DWORD), ("hModule", w.HMODULE),
                        ("szModule", w.WCHAR * 256), ("szExePath", w.WCHAR * 260)]
        snap = k.CreateToolhelp32Snapshot(0x18, pid)
        if snap == ctypes.c_void_p(-1).value:
            raise OSError("Module enumeration failed")
        try:
            m = Module()
            m.dwSize = ctypes.sizeof(m)
            if k.Module32FirstW(snap, ctypes.byref(m)):
                while True:
                    if m.szModule.lower() == EXE.lower():
                        self.base = int(m.modBaseAddr)
                        self.size = int(m.modBaseSize)
                        break
                    if not k.Module32NextW(snap, ctypes.byref(m)):
                        break
        finally:
            k.CloseHandle(snap)
        if not hasattr(self, "base"):
            raise OSError("Fortnite module not found")

    def read(self, addr, length):
        buffer = ctypes.create_string_buffer(length)
        size = ctypes.c_size_t()
        ok = self.k.ReadProcessMemory(self.handle, ctypes.c_void_p(addr),
                                       buffer, length, ctypes.byref(size))
        return buffer.raw if ok and size.value == length else None

    def sections(self):
        h = self.read(self.base, 4096)
        if not h or h[:2] != b"MZ":
            raise ValueError("PE DOS header not readable")
        pe = struct.unpack_from("<I", h, 0x3c)[0]
        if pe > 0xe00 or h[pe:pe + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE header")
        n = struct.unpack_from("<H", h, pe + 6)[0]
        opt = struct.unpack_from("<H", h, pe + 20)[0]
        table = pe + 24 + opt
        if n > 96 or table + n * 40 > len(h):
            raise ValueError("Invalid PE section table")
        result = []
        for i in range(n):
            off = table + i * 40
            size, rva = struct.unpack_from("<II", h, off + 8)
            flags = struct.unpack_from("<I", h, off + 36)[0]
            if not flags & 0x80000000 or rva >= self.size or size == 0:
                continue
            size = min(size, self.size - rva, 128 * 1024 * 1024)
            name = h[off:off + 8].split(b"\x00")[0].decode("ascii", "replace")
            print("Section %s RVA=0x%X bytes=%d" % (name, rva, size), flush=True)
            data = bytearray(size)
            for pos in range(0, size, 4096):
                length = min(4096, size - pos)
                part = self.read(self.base + rva + pos, length)
                if part:
                    data[pos:pos + length] = part
            result.append((rva, data))
        return result

    def close(self):
        self.k.CloseHandle(self.handle)

def find_pid():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD),
                    ("th32ProcessID", w.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                    ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", w.LONG),
                    ("dwFlags", w.DWORD), ("szExeFile", w.WCHAR * 260)]
    k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    k.CreateToolhelp32Snapshot.restype = w.HANDLE
    k.Process32FirstW.argtypes = [w.HANDLE, ctypes.c_void_p]
    k.Process32FirstW.restype = w.BOOL
    k.Process32NextW.argtypes = [w.HANDLE, ctypes.c_void_p]
    k.Process32NextW.restype = w.BOOL
    k.CloseHandle.argtypes = [w.HANDLE]
    snap = k.CreateToolhelp32Snapshot(2, 0)
    if snap == ctypes.c_void_p(-1).value:
        raise OSError("Process snapshot failed")
    try:
        e = Entry()
        e.dwSize = ctypes.sizeof(e)
        if k.Process32FirstW(snap, ctypes.byref(e)):
            while True:
                if e.szExeFile.lower() == EXE.lower():
                    return int(e.th32ProcessID)
                if not k.Process32NextW(snap, ctypes.byref(e)):
                    break
    finally:
        k.CloseHandle(snap)
    raise OSError("Fortnite is not running")

def self_test():
    class Fake:
        def __init__(self):
            self.mem = {}
        def put(self, addr, fmt, *args):
            for i, value in enumerate(struct.pack(fmt, *args)):
                self.mem[addr + i] = value
        def read(self, addr, n):
            values = [self.mem.get(addr + i) for i in range(n)]
            return bytes(values) if all(v is not None for v in values) else None
    base = 0x140000000
    f = Fake()
    r = Reader(f.read, base)
    world, level, gi, players, lp, pc, pawn, camera = [
        0x70000000 + i * 0x10000 for i in range(8)]
    for addr in (level, gi, pc, pawn, camera):
        f.put(addr, "<Q", base + 0x1000)
    f.put(world + 0x30, "<Q", level)
    f.put(gi + 0x38, "<Qii", players, 1, 1)
    f.put(players, "<Q", lp)
    f.put(lp + 0x30, "<Q", pc)
    for name, p in PROFILES.items():
        f.put(base + p["gworld"], "<Q", world)
        f.put(world + p["gi"], "<Q", gi)
        f.put(pc + p["pawn"], "<Q", pawn)
        f.put(pc + p["camera"], "<Q", camera)
        if p["actor_array"] is not None:
            f.put(level + p["actor_array"], "<Q", players)
            f.put(level + p["actor_count"], "<i", 1)
        result = r.check(p["gworld"], p)
        assert result and result[0] >= 11, (name, result)
        data = bytearray(24)
        struct.pack_into("<Q", data, 8, world)
        hits, _, _ = r.scan([(p["gworld"] - 8, data)], p, 20)
        assert hits and hits[0][0] == p["gworld"]
        f.put(gi + 0x38, "<Qii", players, 0, 1)
        assert r.check(p["gworld"], p) is None
        f.put(gi + 0x38, "<Qii", players, 1, 1)
        f.put(base + p["gworld"], "<Q", 0)
        assert r.check(p["gworld"], p) is None
        f.put(base + p["gworld"], "<Q", world)
    print("PASS: profiles A/B, valid chain, scan, empty players, invalid GWorld")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--max-candidates", type=int, default=25000)
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if os.name != "nt":
        print("Live scan requires Windows x64.")
        return 2
    if not 1 <= args.max_candidates <= 1000000:
        ap.error("Invalid --max-candidates")
    p = WinProcess(args.pid or find_pid())
    try:
        print("Fortnite PID=%d base=0x%X image=0x%X" % (p.pid, p.base, p.size))
        print("Both profiles are UNVERIFIED for CL-14550713")
        reader = Reader(p.read, p.base)
        sections = p.sections()
        any_hits = False
        for name, profile in PROFILES.items():
            print("\n=== %s ===" % name)
            print("Expected GWorld RVA=0x%X GI=0x%X Pawn=0x%X Camera=0x%X" %
                  (profile["gworld"], profile["gi"], profile["pawn"], profile["camera"]))
            direct = reader.check(profile["gworld"], profile)
            print("Direct RVA:", "STRUCTURAL MATCH" if direct else "NOT VALIDATED")
            hits, checked, limited = reader.scan(sections, profile, args.max_candidates)
            print("Scanned slots=%d reads=%d truncated=%s" %
                  (checked, reader.read_count, limited))
            if not hits:
                print("NO STRUCTURAL MATCH")
            else:
                any_hits = True
                for rva, score, world, checks in hits[:20]:
                    print("CANDIDATE profile=%s GWorld RVA=0x%X score=%d world=0x%X checks=%s" %
                          (name, rva, score, world, ",".join(checks)))
        print("No GObjects/FNamePool verification. Structural matches are not proof.")
        return 0 if any_hits else 4
    finally:
        p.close()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
