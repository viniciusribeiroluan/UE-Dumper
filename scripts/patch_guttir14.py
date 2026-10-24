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

# Report exactly which engine initialization prerequisite failed.
p = "upstream/Dumper/engine.cpp"
replace_once(p, '''  if (found != 7) return STATUS::ENGINE_FAILED;

  NamePoolData =''', '''  printf("Engine scan: FNamePool=%s, GObjects=%s, Fortnite decrypt=%s\\n",
         (found & 1) ? "matched" : "NOT FOUND",
         (found & 2) ? "matched" : "NOT FOUND",
         (found & 4) ? "matched" : "NOT FOUND");
  if (found != 7) return STATUS::ENGINE_FAILED;
  printf("Candidate addresses: FNamePool=%p GObjects=%p\\n", names, objects);

  NamePoolData =''')
replace_once(p, '''    if (*(uint32*)entry.String().data() != 'enoN') return STATUS::ENGINE_FAILED;''', '''    const auto firstName = entry.String();
    printf("First decoded name: %s\\n", firstName.c_str());
    if (firstName != "None") {
      puts("Name validation failed: first name is not None");
      return STATUS::ENGINE_FAILED;
    }''')
replace_once(p, '''  catch (...) {
    return STATUS::ENGINE_FAILED;
  }''', '''  catch (...) {
    puts("Name validation threw an exception");
    return STATUS::ENGINE_FAILED;
  }''')


# Diagnostic-only scan: look for RIP-relative references to a plausible UE4
# FNamePool header. No decryption code is executed and no SDK is generated.
p = "upstream/Dumper/engine.cpp"
replace_once(p, '''  if (found != 7) return STATUS::ENGINE_FAILED;
  printf("Candidate addresses:''', '''  if (found != 7) {
    puts("Scanning alternate RIP-relative FNamePool references (diagnostic only)...");
    auto dos = (PIMAGE_DOS_HEADER)image;
    auto nt = (PIMAGE_NT_HEADERS)((uint8*)image + dos->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;
    uintptr_t imageBegin = (uintptr_t)image;
    uintptr_t imageEnd = imageBegin + imageSize;
    uint32 references = 0, plausible = 0, printed = 0;
    IterateExSections(image, [&](void* sectionStart, void* sectionEnd) -> bool {
      for (auto at = (uint8*)sectionStart; at + 7 <= (uint8*)sectionEnd; ++at) {
        // LEA reg,[RIP+disp32]: 48/4C 8D 05/0D/15/1D/25/2D/35/3D
        if ((at[0] != 0x48 && at[0] != 0x4C) || at[1] != 0x8D ||
            (at[2] & 0xC7) != 0x05) continue;
        ++references;
        int32 displacement = 0;
        memcpy(&displacement, at + 3, sizeof(displacement));
        uintptr_t target = (uintptr_t)(at + 7) + displacement;
        if (target < imageBegin || target > imageEnd - 64) continue;
        uintptr_t remote = (uintptr_t)Base + (target - imageBegin);
        uint8 header[64]{};
        if (!Read((void*)remote, header, sizeof(header))) continue;
        // Also check references to nearby fields of the pool.
        for (uint32 adjust : {0u, 8u, 16u}) {
          uint32 block = 0, cursor = 0;
          uint64 block0 = 0;
          memcpy(&block, header + adjust + 8, 4);
          memcpy(&cursor, header + adjust + 12, 4);
          memcpy(&block0, header + adjust + 16, 8);
          if (block >= 8192 || cursor == 0 || cursor > 131072 ||
              block0 < 0x10000) continue;
          uint8 first[8]{};
          if (!Read((void*)block0, first, sizeof(first))) continue;
          // UE4 FNamePool begins with the "None" entry (four characters).
          // Reject arbitrary UTF-16 strings and other mapped pointers.
          uint16 firstHeader = 0;
          memcpy(&firstHeader, first, 2);
          const bool header64 = (firstHeader >> 6) == 4;
          const bool header1 = (firstHeader >> 1) == 4;
          if (!header64 && !header1) continue;
          if (block > 2048 || cursor < 32 || cursor > 65536 ||
              (block0 & 1) != 0) continue;
          ++plausible;
          if (printed++ < 20) {
            printf("FNamePool strong candidate: RVA=0x%llX adjust=%u block=%u cursor=%u block0=0x%llX header=0x%04X header-format=%s raw=%02X %02X %02X %02X %02X %02X\\n",
              (unsigned long long)(target - imageBegin), adjust,
              block, cursor, (unsigned long long)block0,
              (unsigned)firstHeader, header64 ? "len>>6" : "len>>1",
              first[0], first[1], first[2], first[3], first[4], first[5]);
          }
        }
      }
      return false;
    });
    printf("Alternate FNamePool scan: %u LEA references, %u four-char-first-entry candidates (showing up to 20)\\n",
           references, plausible);
    // Independently inspect writable sections, as some pool globals have no
    // matching RIP-relative LEA in the original Fortnite signature family.
    uint32 dataHeaders = 0, dataPrinted = 0;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (uint32 si = 0; si < nt->FileHeader.NumberOfSections; ++si, ++section) {
      if (!(section->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
      size_t start = section->VirtualAddress;
      size_t end = start + section->Misc.VirtualSize;
      if (start >= imageSize) continue;
      if (end > imageSize) end = imageSize;
      for (size_t off = (start + 7) & ~size_t(7); off + 32 <= end; off += 8) {
        uint8* candidate = (uint8*)image + off;
        uint32 block = 0, cursor = 0;
        uint64 block0 = 0;
        memcpy(&block, candidate + 8, 4);
        memcpy(&cursor, candidate + 12, 4);
        memcpy(&block0, candidate + 16, 8);
        if (block > 2048 || cursor < 32 || cursor > 65536 ||
            block0 < 0x10000 || block0 >= 0x0000800000000000ull ||
            (block0 & 1) != 0) continue;
        uint8 first[8]{};
        if (!Read((void*)block0, first, sizeof(first))) continue;
        uint16 firstHeader = 0;
        memcpy(&firstHeader, first, 2);
        if ((firstHeader >> 6) != 4 && (firstHeader >> 1) != 4) continue;
        ++dataHeaders;
        if (dataPrinted++ < 20) {
          printf("FNamePool data candidate: RVA=0x%llX block=%u cursor=%u block0=0x%llX firstHeader=0x%04X raw=%02X %02X %02X %02X %02X %02X\\n",
                 (unsigned long long)off, block, cursor,
                 (unsigned long long)block0, (unsigned)firstHeader,
                 first[0], first[1], first[2], first[3], first[4], first[5]);
        }
      }
    }
    printf("Writable-section FNamePool scan: %u candidates (showing up to 20)\\n", dataHeaders);
    puts("Fortnite decrypt signature missing; no SDK generation attempted.");
    return STATUS::ENGINE_FAILED;
  }
  printf("Candidate addresses:''')

print("Fortnite 14.40 FNamePool strict header validation and writable-section scan applied")
