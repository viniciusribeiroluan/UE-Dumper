"""Fortnite 14.40 read-only UWorld pointer-chain probe.
The member offsets below come from a 14.30 reference and are UNVERIFIED for 14.40.
Run: Fortnite1440_LayoutProbe.exe > resultado_probe.txt 2>&1
Tests: Fortnite1440_LayoutProbe.exe --self-test
"""
import argparse
import ctypes
import os
import struct
import sys

EXE = "FortniteClient-Win64-Shipping.exe"
GWORLD_1430 = 0x92B3420
GOBJECTS_1430 = 0x9178F08
GNAMES_1430 = 0x914CBC0

def pointer(v):
    return v is not None and 0x10000 <= v < 0x800000000000 and v % 8 == 0

class Probe:
    def __init__(self, process, base, limit=25000):
        self.process, self.base, self.limit = process, base, limit
        self.reads = 0

    def read(self, address, length):
        if not pointer(address) or length < 1 or length > 4096:
            return None
        self.reads += 1
        return self.process.read(address, length)

    def qword(self, address):
        b = self.read(address, 8)
        return struct.unpack("<Q", b)[0] if b is not None and len(b) == 8 else None

    def array(self, address, max_size):
        b = self.read(address, 16)
        if b is None or len(b) != 16:
            return None
        data, count, capacity = struct.unpack("<Qii", b)
        if not 0 <= count <= capacity <= max_size:
            return None
        if count and not pointer(data):
            return None
        return data, count

    def inspect(self, slot):
        world = self.qword(slot)
        if not pointer(world):
            return None
        level = self.qword(world + 0x30)
        instance = self.qword(world + 0x180)
        if not pointer(level) or not pointer(instance) or level == instance:
            return None
        if not pointer(self.qword(level)) or not pointer(self.qword(instance)):
            return None
        players = self.array(instance + 0x38, 16)
        if players is None or not 1 <= players[1] <= 4:
            return None
        player = self.qword(players[0])
        if not pointer(player):
            return None
        controller = self.qword(player + 0x30)
        if not pointer(controller) or not pointer(self.qword(controller)):
            return None
        checks = ["PersistentLevel", "OwningGameInstance", "LocalPlayers[0]", "PlayerController"]
        score = 7
        levels = self.array(world + 0x138, 100000)
        if levels is not None and levels[1] > 0 and pointer(self.qword(levels[0])):
            score += 2
            checks.append("Levels")
        state = self.qword(world + 0x120)
        if pointer(state) and pointer(self.qword(state)):
            score += 1
            checks.append("GameState")
        return (slot - self.base, world, score, checks)

    def scan(self, sections):
        slots = []
        for rva, data in sections:
            for offset in range(0, len(data) - 7, 8):
                if pointer(struct.unpack_from("<Q", data, offset)[0]):
                    slots.append(rva + offset)
        slots.sort(key=lambda r: (abs(r - GWORLD_1430) > 0x200000, abs(r - GWORLD_1430), r))
        results = []
        for rva in slots[:self.limit]:
            hit = self.inspect(self.base + rva)
            if hit is not None:
                results.append(hit)
        results.sort(key=lambda h: (-h[2], abs(h[0] - GWORLD_1430)))
        return results, min(len(slots), self.limit), len(slots) > self.limit

class WindowsProcess:
    def __init__(self, pid):
        from ctypes import wintypes as w
        self.pid = pid
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.k
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenProcess.restype = w.HANDLE
        k.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
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
            raise OSError("OpenProcess failed: Win32 error %d" % ctypes.get_last_error())
        class Module(ctypes.Structure):
            _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD),
                        ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD),
                        ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.c_void_p),
                        ("modBaseSize", w.DWORD), ("hModule", w.HMODULE),
                        ("szModule", w.WCHAR * 256), ("szExePath", w.WCHAR * 260)]
        snap = k.CreateToolhelp32Snapshot(0x18, pid)
        if snap == ctypes.c_void_p(-1).value:
            raise OSError("Cannot enumerate modules")
        try:
            entry = Module()
            entry.dwSize = ctypes.sizeof(entry)
            if k.Module32FirstW(snap, ctypes.byref(entry)):
                while True:
                    if entry.szModule.lower() == EXE.lower():
                        self.base = int(entry.modBaseAddr)
                        self.size = int(entry.modBaseSize)
                        break
                    if not k.Module32NextW(snap, ctypes.byref(entry)):
                        break
        finally:
            k.CloseHandle(snap)
        if not hasattr(self, "base"):
            raise OSError("Fortnite module not found in PID %d" % pid)

    def read(self, address, length):
        buf = ctypes.create_string_buffer(length)
        done = ctypes.c_size_t()
        ok = self.k.ReadProcessMemory(self.handle, ctypes.c_void_p(address), buf, length, ctypes.byref(done))
        return buf.raw if ok and done.value == length else None

    def close(self):
        self.k.CloseHandle(self.handle)

    def sections(self):
        header = self.read(self.base, 4096)
        if not header or header[:2] != b"MZ":
            raise ValueError("Cannot read DOS header")
        pe = struct.unpack_from("<I", header, 0x3c)[0]
        if pe > 0xE00 or header[pe:pe + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE header")
        count = struct.unpack_from("<H", header, pe + 6)[0]
        opt_size = struct.unpack_from("<H", header, pe + 20)[0]
        table = pe + 24 + opt_size
        if count > 96 or table + count * 40 > len(header):
            raise ValueError("Invalid section table")
        result = []
        for i in range(count):
            off = table + i * 40
            name = header[off:off + 8].split(b"\x00")[0].decode("ascii", "replace")
            size, rva = struct.unpack_from("<II", header, off + 8)
            flags = struct.unpack_from("<I", header, off + 36)[0]
            if not flags & 0x80000000 or rva >= self.size or not size:
                continue
            size = min(size, self.size - rva, 128 * 1024 * 1024)
            print("Reading writable section %s RVA=0x%X bytes=%d" % (name, rva, size), flush=True)
            data = bytearray(size)
            for j in range(0, size, 4096):
                length = min(4096, size - j)
                part = self.read(self.base + rva + j, length)
                if part:
                    data[j:j + length] = part
            result.append((rva, data))
        return result

def find_pid():
    from ctypes import wintypes as w
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
        entry = Entry()
        entry.dwSize = ctypes.sizeof(entry)
        if k.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == EXE.lower():
                    return int(entry.th32ProcessID)
                if not k.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        k.CloseHandle(snap)
    raise OSError("Fortnite is not running")

def self_test():
    class Memory:
        def __init__(self):
            self.data = {}
        def put(self, addr, fmt, *values):
            for i, b in enumerate(struct.pack(fmt, *values)):
                self.data[addr + i] = b
        def read(self, addr, length):
            values = [self.data.get(addr + i) for i in range(length)]
            return bytes(values) if all(x is not None for x in values) else None
    base = 0x140000000
    slot = base + GWORLD_1430
    world, level, gi, players, lp, pc = [0x70000000 + 0x10000 * i for i in range(6)]
    m = Memory()
    for address, value in [(slot, world), (world + 0x30, level),
                           (world + 0x180, gi), (level, base + 0x1000),
                           (gi, base + 0x1000), (players, lp),
                           (lp + 0x30, pc), (pc, base + 0x1000),
                           (world + 0x120, 0)]:
        m.put(address, "<Q", value)
    m.put(gi + 0x38, "<Qii", players, 1, 1)
    m.put(world + 0x138, "<Qii", players, 1, 1)
    p = Probe(m, base)
    assert p.inspect(slot)[0] == GWORLD_1430
    data = bytearray(24)
    struct.pack_into("<Q", data, 8, world)
    assert len(p.scan([(GWORLD_1430 - 8, data)])[0]) == 1
    m.put(gi + 0x38, "<Qii", players, 0, 1)
    assert p.inspect(slot) is None
    m.put(gi + 0x38, "<Qii", players, 1, 1)
    m.put(lp + 0x30, "<Q", 0)
    assert p.inspect(slot) is None
    print("PASS: valid chain, writable section scan, empty players, invalid chain")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--max-candidates", type=int, default=25000)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if os.name != "nt":
        print("Live scan requires Windows x64.")
        return 2
    if not 1 <= args.max_candidates <= 1000000:
        parser.error("Invalid --max-candidates")
    proc = WindowsProcess(args.pid or find_pid())
    try:
        print("Fortnite PID=%d base=0x%X image size=0x%X" % (proc.pid, proc.base, proc.size))
        print("14.30 REFERENCE ONLY: GWorld=0x%X GObjects=0x%X GNames=0x%X" %
              (GWORLD_1430, GOBJECTS_1430, GNAMES_1430))
        probe = Probe(proc, proc.base, args.max_candidates)
        print("14.30 GWorld RVA chain:", "MATCH" if probe.inspect(proc.base + GWORLD_1430) else "NOT VALIDATED")
        hits, checked, limited = probe.scan(proc.sections())
        print("Inspected %d candidate slots, %d reads, scan truncated=%s" %
              (checked, probe.reads, limited))
        if not hits:
            print("NO VALIDATED CANDIDATES. Could be loading, different layout, or encrypted pointers.")
            return 4
        for rva, world, score, checks in hits[:20]:
            print("CANDIDATE GWorld RVA=0x%X VA=0x%X world=0x%X score=%d checks=%s" %
                  (rva, proc.base + rva, world, score, ",".join(checks)))
        print("These are structural matches, NOT confirmed offsets. GObjects/FNamePool not validated.")
        return 0
    finally:
        proc.close()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
