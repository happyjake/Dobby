
#include "dobby/dobby_internal.h"
#include "core/arch/Cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__ANDROID__)
#include <android/log.h>
#define DOBBY_DIAG(lvl, fmt, ...) \
  __android_log_print(ANDROID_LOG_##lvl, "Dobby-patch", fmt, ##__VA_ARGS__)
#else
#define DOBBY_DIAG(lvl, fmt, ...) ((void)0)
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

#ifndef __NR_memfd_create
#define __NR_memfd_create 279  // arm64 Linux
#endif

#if !defined(__APPLE__)

// Android 16+ zygote children have MDWE (PR_MDWE_REFUSE_EXEC_GAIN)
// inherited from zygote. Consequences observed on nezha (SM8850) / A16:
//
//   open("/proc/self/mem", O_RDWR)   -> EACCES (SELinux blocks writes)
//   mprotect(R+W) on libart code     -> OK (dropping EXEC is fine)
//   mprotect(R+X) after the write    -> EACCES (MDWE refuses EXEC gain)
//   mmap(MAP_FIXED, R+X, memfd) over
//     an existing R+W VMA            -> EACCES (MDWE evaluates against
//                                        the existing VMA's flags)
//
// Once a libart page is transitioned to R+W, it is *permanently*
// non-executable for the life of this process. We cannot let the page
// lose EXEC even transiently, or the hook is dead.
//
// Strategy: build a new R+X mapping from a memfd and atomically swap it
// over the target page WHILE the target is still R+X.
//
//   1. Read the original page bytes straight out of the R+X libart VMA
//      (reading an R+X page is fine; the page protection has EXEC, not
//      only WRITE).
//   2. Overlay the trampoline bytes at the correct offset.
//   3. memfd_create(MFD_EXEC | MFD_CLOEXEC), ftruncate, write the buffer.
//   4. mmap(target, PROT_READ|PROT_EXEC, MAP_FIXED|MAP_PRIVATE, memfd, 0)
//      replaces the VMA atomically. During the MDWE check:
//        - existing VMA is R+X (has VM_EXEC)
//        - new prot is PROT_READ|PROT_EXEC (no PROT_WRITE)
//      Neither MDWE clause fires, so the swap is permitted.
//
// On non-MDWE environments (rooted processes, pre-A16 Android, Linux
// desktops) the same path still works -- we're just paying a memfd cost
// unconditionally, which is O(page_size) copy + one syscall round. No
// measurable difference for LSPlant's ~20 init hooks.

static int memfd_patch_page(uintptr_t patch_page, size_t page_size,
                            uintptr_t offset_in_page,
                            const uint8_t *trampoline_bytes,
                            size_t trampoline_size) {
  if (offset_in_page + trampoline_size > page_size) {
    DOBBY_DIAG(ERROR, "memfd_patch: tramp %zu @ off %zu overflows page_size %zu",
               trampoline_size, offset_in_page, page_size);
    return -1;
  }

  uint8_t *staged = (uint8_t *)malloc(page_size);
  if (!staged) {
    DOBBY_DIAG(ERROR, "memfd_patch: malloc(%zu) failed", page_size);
    return -1;
  }

  // Step 1: snapshot existing page. Reading an R+X mapping is legal.
  memcpy(staged, (void *)patch_page, page_size);
  // Step 2: overlay trampoline.
  memcpy(staged + offset_in_page, trampoline_bytes, trampoline_size);

  // Step 3: allocate exec-capable memfd and fill it.
  int memfd = (int)syscall(__NR_memfd_create, "dobby-patch",
                           MFD_CLOEXEC | MFD_EXEC);
  if (memfd < 0) {
    int e1 = errno;
    memfd = (int)syscall(__NR_memfd_create, "dobby-patch", MFD_CLOEXEC);
    if (memfd < 0) {
      DOBBY_DIAG(ERROR,
                 "memfd_patch: memfd_create MFD_EXEC errno=%d (%s), "
                 "plain errno=%d (%s)",
                 e1, strerror(e1), errno, strerror(errno));
      free(staged);
      return -1;
    }
  }
  if (ftruncate(memfd, page_size) != 0) {
    int e = errno;
    DOBBY_DIAG(ERROR, "memfd_patch: ftruncate errno=%d (%s)", e, strerror(e));
    close(memfd);
    free(staged);
    errno = e;
    return -1;
  }
  ssize_t w = write(memfd, staged, page_size);
  int we = errno;
  free(staged);
  if (w != (ssize_t)page_size) {
    DOBBY_DIAG(ERROR, "memfd_patch: write returned %zd errno=%d (%s)",
               w, we, strerror(we));
    close(memfd);
    errno = we;
    return -1;
  }

  // Step 4: atomic swap. Target is currently R+X, new mapping is R+X,
  // no PROT_WRITE requested -- MDWE allows it.
  void *m = mmap((void *)patch_page, page_size, PROT_READ | PROT_EXEC,
                 MAP_FIXED | MAP_PRIVATE, memfd, 0);
  if (m == MAP_FAILED) {
    int e = errno;
    DOBBY_DIAG(ERROR, "memfd_patch: mmap(MAP_FIXED|R+X) errno=%d (%s) page=0x%lx",
               e, strerror(e), (unsigned long)patch_page);
    close(memfd);
    errno = e;
    return -1;
  }
  close(memfd);
  DOBBY_DIAG(INFO,
             "memfd_patch ok: page=0x%lx off=%zu tramp=%zu",
             (unsigned long)patch_page, offset_in_page, trampoline_size);
  return 0;
}

PUBLIC int DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  int page_size = (int)sysconf(_SC_PAGESIZE);
  uintptr_t addr = (uintptr_t)address;
  uintptr_t patch_page = ALIGN_FLOOR(addr, page_size);
  uintptr_t patch_end_page = ALIGN_FLOOR(addr + buffer_size, page_size);

  if (patch_page == patch_end_page) {
    if (memfd_patch_page(patch_page, (size_t)page_size,
                         addr - patch_page, buffer, buffer_size) != 0) {
      DOBBY_DIAG(ERROR, "DobbyCodePatch: single-page patch at %p failed", address);
      return -1;
    }
  } else {
    // Trampoline straddles page boundary: patch each page separately.
    size_t first_len = (size_t)(patch_end_page - addr);
    size_t tail_len = (size_t)buffer_size - first_len;
    if (memfd_patch_page(patch_page, (size_t)page_size,
                         addr - patch_page, buffer, first_len) != 0) {
      DOBBY_DIAG(ERROR, "DobbyCodePatch: head page %p failed", address);
      return -1;
    }
    if (memfd_patch_page(patch_end_page, (size_t)page_size,
                         0, buffer + first_len, tail_len) != 0) {
      DOBBY_DIAG(ERROR, "DobbyCodePatch: tail page 0x%lx failed",
                 (unsigned long)patch_end_page);
      return -1;
    }
  }

  addr_t clear_start_ = (addr_t)address;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + buffer_size));
#endif
  return 0;
}

#endif
