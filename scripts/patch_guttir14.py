"""Patch guttir14/UnrealDumper-4.25 for a safer Fortnite 14.40 test.
The upstream source is pinned by commit in the build workflow.
"""
from pathlib import Path

def replace_once(path, old, new):
    file = Path(path)
    content = file.read_text(encoding="utf-8")
    assert content.count(old) == 1, f"Expected one match in {path}, found {content.count(old)}: {old[:80]}"
    file.write_text(content.replace(old, new), encoding="utf-8")

p = "upstream/Dumper/dumper.cpp"
replace_once(p, '#include <Windows.h>', '#include <Windows.h>\n#include <TlHelp32.h>')
replace_once(p, '''    HWND hWnd = FindWindowA("UnrealWindow", nullptr);
    if (!hWnd) {
      return STATUS::WINDOW_NOT_FOUND;
    };
    GetWindowThreadProcessId(hWnd, (DWORD*)(&pid));
    if (!pid) {
      return STATUS::PROCESS_NOT_FOUND;
    };''', '''    // Select Fortnite explicitly instead of another UE game window.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return STATUS::PROCESS_NOT_FOUND;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
      do {
        if (_wcsicmp(pe.szExeFile, L"FortniteClient-Win64-Shipping.exe") == 0) {
          pid = pe.th32ProcessID;
          break;
        }
      } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    if (!pid) return STATUS::PROCESS_NOT_FOUND;
    printf("Fortnite PID: %u\\n", pid);''')
replace_once(p, '''    if (!Read((void*)Base, Image, size)) {
      return STATUS::CANNOT_READ;
    }

    return EngineInit(game.string(), Image);''', '''    // One unreadable memory page should not invalidate the entire ~176 MiB image.
    // VirtualAlloc gives us zero-filled bytes for pages that cannot be read.
    uint64 failedPages = 0, readableBytes = 0;
    for (uint64 offset = 0; offset < size; offset += 4096) {
      uint64 count = (size - offset < 4096) ? (size - offset) : 4096;
      if (Read((void*)(Base + offset), (uint8*)Image + offset, count)) {
        readableBytes += count;
      } else {
        failedPages++;
      }
    }
    printf("Image read: %llu/%llu bytes; unreadable pages: %llu\\n",
           (unsigned long long)readableBytes,
           (unsigned long long)size,
           (unsigned long long)failedPages);
    if (readableBytes < size * 9 / 10) return STATUS::CANNOT_READ;
    return EngineInit(game.string(), Image);''')
p = "upstream/Dumper/engine.cpp"
replace_once(p, '''  NamePoolData = *(decltype(NamePoolData)*)names;
  ObjObjects = *(decltype(ObjObjects)*)objects;

  auto entry = UE_FNameEntry(NamePoolData.GetEntry(0));''', '''  NamePoolData = *(decltype(NamePoolData)*)names;
  ObjObjects = *(decltype(ObjObjects)*)objects;

  printf("FNamePool: block=%u cursor=%u block0=%p\\n",
         NamePoolData.CurrentBlock, NamePoolData.CurrentByteCursor, NamePoolData.Blocks[0]);
  printf("Objects: elements=%u chunks=%u\\n",
         ObjObjects.NumElements, ObjObjects.NumChunks);
  if (NamePoolData.CurrentBlock >= 8192 ||
      NamePoolData.CurrentByteCursor > 131072 ||
      !NamePoolData.Blocks[0] ||
      ObjObjects.NumElements == 0 || ObjObjects.NumElements > 5000000 ||
      ObjObjects.NumChunks == 0 || ObjObjects.NumChunks > 8192) {
    puts("Invalid FNamePool/GObjects layout; stopping safely");
    return STATUS::ENGINE_FAILED;
  }
  auto entry = UE_FNameEntry(NamePoolData.GetEntry(0));
  if (!entry) return STATUS::ENGINE_FAILED;''')
p = "upstream/Dumper/generic.cpp"
replace_once(p, '''    if (len) {
      char buf[1024];''', '''    if (len && len < 1024) {
      char buf[1024]{};''')
print("Fortnite 14.40 compatibility and safety patches applied")
