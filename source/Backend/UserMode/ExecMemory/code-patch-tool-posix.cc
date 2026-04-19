
#include "dobby/dobby_internal.h"
#include "core/arch/Cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#if !defined(__APPLE__)

// On Android 16+ W^X is strictly enforced: mprotect(RWX) fails with
// EACCES on executable pages, and even the mprotect(RW)+memcpy+restore(RX)
// dance can fail if the page is sealed (mseal) or the kernel policy
// denies re-adding PROT_EXEC after writable-downgrade.
//
// To avoid both problems we write via /proc/self/mem, which bypasses
// VMA protection entirely (a kernel-side write, not a user store).
// Falls back to the mprotect dance for environments where /proc/self/mem
// is restricted.
static int write_via_proc_mem(void *address, const uint8_t *buffer, size_t size) {
  int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
  if (fd < 0) return -1;
  off_t off = (off_t)(uintptr_t)address;
  ssize_t n = pwrite(fd, buffer, size, off);
  int saved = errno;
  close(fd);
  if (n == (ssize_t)size) return 0;
  errno = saved;
  return -1;
}

static int write_via_mprotect(void *address, const uint8_t *buffer, size_t size, int page_size) {
  uintptr_t patch_page = ALIGN_FLOOR(address, page_size);
  uintptr_t patch_end_page = ALIGN_FLOOR((uintptr_t)address + size, page_size);

  // W^X safe: try RW first (the page was RX, now RW, then restore RX).
  // Fall back to legacy RWX for pre-A16 environments.
  if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_WRITE) != 0) {
    if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      return -1;
    }
  }
  if (patch_page != patch_end_page) {
    if (mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_WRITE) != 0) {
      mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    }
  }

  memcpy(address, buffer, size);

  // Restore. If the kernel refuses RX (e.g. sealed page), at least report it.
  if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_EXEC) != 0) {
    return -1;
  }
  if (patch_page != patch_end_page) {
    mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_EXEC);
  }
  return 0;
}

PUBLIC int DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  int page_size = (int)sysconf(_SC_PAGESIZE);

  // Primary: /proc/self/mem — protection-agnostic write
  int rc = write_via_proc_mem(address, buffer, buffer_size);
  if (rc != 0) {
    // Fallback for unusual environments where /proc/self/mem is blocked
    rc = write_via_mprotect(address, buffer, buffer_size, page_size);
    if (rc != 0) return rc;
  }

  addr_t clear_start_ = (addr_t)address;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + buffer_size));
#endif
  return 0;
}

#endif
