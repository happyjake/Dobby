
#include "dobby/dobby_internal.h"
#include "core/arch/Cpu.h"

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#if !defined(__APPLE__)

// Android 16+ enforces W^X strictly: mprotect(RWX) fails with EACCES for
// pages that are currently executable, returning -1. The original code did
// not check the return value, then attempted memcpy into a page that
// remained read-only, crashing with SIGSEGV in __memcpy_aarch64_nt.
//
// Fix: first try RW (no EXEC) which is always allowed; fall back to the
// legacy RWX attempt for older Android where that path is needed.
static int dobby_make_writable(void *page, size_t page_size) {
  if (mprotect(page, page_size, PROT_READ | PROT_WRITE) == 0) return 0;
  int err_rw = errno;
  if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) return 0;
  errno = err_rw;
  return -1;
}

PUBLIC int DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  int page_size = (int)sysconf(_SC_PAGESIZE);
  uintptr_t patch_page = ALIGN_FLOOR(address, page_size);
  uintptr_t patch_end_page = ALIGN_FLOOR((uintptr_t)address + buffer_size, page_size);

  // W^X safe: make writable (drop EXEC temporarily)
  if (dobby_make_writable((void *)patch_page, page_size) != 0) {
    return -1;
  }
  if (patch_page != patch_end_page) {
    if (dobby_make_writable((void *)patch_end_page, page_size) != 0) {
      mprotect((void *)patch_page, page_size, PROT_READ | PROT_EXEC);
      return -1;
    }
  }

  // patch buffer
  memcpy(address, buffer, buffer_size);

  // restore page permission
  mprotect((void *)patch_page, page_size, PROT_READ | PROT_EXEC);
  if (patch_page != patch_end_page) {
    mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_EXEC);
  }

  addr_t clear_start_ = (addr_t)address;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + buffer_size));
#endif
  return 0;
}

#endif
