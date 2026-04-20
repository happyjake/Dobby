
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
// Dobby's DEBUG_LOG is compiled out in release builds (no DOBBY_DEBUG). We
// need these diagnostics to land in logcat unconditionally when a patch
// restore fails, because that failure causes silent page-protection damage
// that SIGSEGVs minutes later in unrelated code paths.
#define DOBBY_DIAG(lvl, fmt, ...) \
  __android_log_print(ANDROID_LOG_##lvl, "Dobby-patch", fmt, ##__VA_ARGS__)
#else
#define DOBBY_DIAG(lvl, fmt, ...) ((void)0)
#endif

// memfd_create flags -- not always in older <sys/mman.h> on NDK r27
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

#if !defined(__APPLE__)

// On Android 16+ W^X is strictly enforced:
//
// 1) mprotect(PROT_READ|PROT_WRITE|PROT_EXEC) silently drops EXEC (or fails
//    with EACCES), leaving the page RW-only. memcpy then succeeds but
//    CPU branches into the page SIGSEGV with SEGV_ACCERR.
//
// 2) /proc/self/mem pwrite bypasses VMA protection checks, but the kernel
//    strips PROT_EXEC from the VMA as part of the write (COW on
//    file-backed executable mappings). The bytes are correct but the page
//    is no longer executable.
//
// 3) On zygote64 children, mprotect(R+X) to re-add PROT_EXEC after a W
//    transition is blocked by MDWE (PR_MDWE_REFUSE_EXEC_GAIN), returning
//    EACCES. This is what bites Vector/LSPlant on nezha -- patching
//    succeeds, protection restore silently fails, every indirect call
//    into the page (virtual dispatch in libart) SIGSEGVs with
//    "trying to execute non-executable memory".
//
// Fix:
//   a) Try /proc/self/mem pwrite first (primary path).
//   b) If that fails, do the mprotect dance (R+W, memcpy, try R+X).
//   c) If force_rx fails with MDWE/EACCES, fall back to a
//      memfd-backed mmap(MAP_FIXED, R+X) swap. This bypasses MDWE
//      because the new VMA is born R+X -- it never had PROT_WRITE, so
//      map_deny_write_exec doesn't fire.
//
// The memfd-swap path: allocate a memfd, write the *current contents*
// of the page (which already contains the trampoline after step b), and
// mmap(MAP_FIXED) it over the target page with R+X. This atomically
// replaces the broken R+W VMA with a functioning R+X one that carries
// the same bytes. Adjacent libart code on the same page is preserved
// because we copy the whole page first.

static int memfd_swap_to_rx(uintptr_t patch_page, size_t page_size) {
  // 1. Read current (R+W) contents.
  uint8_t *snapshot = (uint8_t *)malloc(page_size);
  if (!snapshot) {
    DOBBY_DIAG(ERROR, "memfd_swap: malloc %zu failed", page_size);
    return -1;
  }
  memcpy(snapshot, (void *)patch_page, page_size);

  // 2. memfd_create (prefer MFD_EXEC so the kernel knows we'll mmap R+X).
  //    On arm64 Linux/Android, __NR_memfd_create == 279.
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
  int memfd = (int)syscall(__NR_memfd_create, "dobby-patch", MFD_CLOEXEC | MFD_EXEC);
  if (memfd < 0) {
    int err1 = errno;
    memfd = (int)syscall(__NR_memfd_create, "dobby-patch", MFD_CLOEXEC);
    if (memfd < 0) {
      DOBBY_DIAG(ERROR,
                 "memfd_swap: memfd_create failed: MFD_EXEC errno=%d (%s), "
                 "plain errno=%d (%s)",
                 err1, strerror(err1), errno, strerror(errno));
      free(snapshot);
      return -1;
    }
  }

  // 3. Fill memfd with the page snapshot.
  if (ftruncate(memfd, page_size) != 0) {
    DOBBY_DIAG(ERROR, "memfd_swap: ftruncate(memfd, %zu) errno=%d (%s)",
               page_size, errno, strerror(errno));
    close(memfd);
    free(snapshot);
    return -1;
  }
  ssize_t w = write(memfd, snapshot, page_size);
  if (w != (ssize_t)page_size) {
    DOBBY_DIAG(ERROR, "memfd_swap: write(memfd) returned %zd errno=%d (%s)",
               w, errno, strerror(errno));
    close(memfd);
    free(snapshot);
    return -1;
  }
  free(snapshot);

  // 4. MAP_FIXED-swap over the target page with R+X. MDWE allows this
  //    because the new VMA is born with exec and never has write.
  void *mapped = mmap((void *)patch_page, page_size, PROT_READ | PROT_EXEC,
                      MAP_FIXED | MAP_PRIVATE, memfd, 0);
  if (mapped == MAP_FAILED) {
    int err = errno;
    DOBBY_DIAG(ERROR, "memfd_swap: mmap(MAP_FIXED|R+X) errno=%d (%s) page=0x%lx",
               err, strerror(err), (unsigned long)patch_page);
    close(memfd);
    errno = err;
    return -1;
  }
  close(memfd);
  DOBBY_DIAG(INFO, "memfd_swap ok: page=0x%lx now R+X via memfd",
             (unsigned long)patch_page);
  return 0;
}

static int force_rx(void *page, size_t size) {
  int r = mprotect(page, size, PROT_READ | PROT_EXEC);
  if (r == 0) {
    DOBBY_DIAG(INFO, "force_rx mprotect(R+X) ok: page=%p size=%zu", page, size);
    return 0;
  }
  int err = errno;
  DOBBY_DIAG(WARN,
             "force_rx mprotect(R+X) failed: page=%p size=%zu errno=%d (%s) -- "
             "attempting memfd-swap fallback",
             page, size, err, strerror(err));
  if (memfd_swap_to_rx((uintptr_t)page, size) == 0) {
    return 0;
  }
  DOBBY_DIAG(ERROR,
             "force_rx: both mprotect and memfd-swap failed for page %p; "
             "hook will fail and caller must not invoke the trampoline",
             page);
  errno = err;
  return -1;
}

static int write_via_proc_mem(void *address, const uint8_t *buffer, size_t size) {
  int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    DOBBY_DIAG(WARN, "open(/proc/self/mem) failed: errno=%d (%s)", errno, strerror(errno));
    return -1;
  }
  off_t off = (off_t)(uintptr_t)address;
  ssize_t n = pwrite(fd, buffer, size, off);
  int saved = errno;
  close(fd);
  if (n == (ssize_t)size) return 0;
  DOBBY_DIAG(WARN, "pwrite(/proc/self/mem, %p, %zu) returned %zd errno=%d (%s)",
             address, size, n, saved, strerror(saved));
  errno = saved;
  return -1;
}

static int write_via_mprotect(void *address, const uint8_t *buffer, size_t size,
                              uintptr_t patch_page, uintptr_t patch_end_page,
                              int page_size) {
  if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_WRITE) != 0) {
    int err1 = errno;
    if (mprotect((void *)patch_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      DOBBY_DIAG(ERROR,
                 "mprotect(RW / RWX) both failed for patch_page=%p: "
                 "RW errno=%d (%s), RWX errno=%d (%s)",
                 (void *)patch_page, err1, strerror(err1), errno, strerror(errno));
      return -1;
    }
  }
  if (patch_page != patch_end_page) {
    if (mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_WRITE) != 0) {
      int err1 = errno;
      if (mprotect((void *)patch_end_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        DOBBY_DIAG(ERROR,
                   "mprotect(RW / RWX) both failed for patch_end_page=%p: "
                   "RW errno=%d (%s), RWX errno=%d (%s)",
                   (void *)patch_end_page, err1, strerror(err1), errno, strerror(errno));
      }
    }
  }
  memcpy(address, buffer, size);
  return 0;
}

PUBLIC int DobbyCodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
#if defined(__ANDROID__) || defined(__linux__)
  int page_size = (int)sysconf(_SC_PAGESIZE);
  uintptr_t patch_page = ALIGN_FLOOR(address, page_size);
  uintptr_t patch_end_page = ALIGN_FLOOR((uintptr_t)address + buffer_size, page_size);

  // Primary: /proc/self/mem, protection-agnostic write.
  int rc = write_via_proc_mem(address, buffer, buffer_size);
  if (rc != 0) {
    DOBBY_DIAG(WARN, "proc_mem write failed for %p, falling back to mprotect path", address);
    rc = write_via_mprotect(address, buffer, buffer_size, patch_page, patch_end_page, page_size);
    if (rc != 0) {
      DOBBY_DIAG(ERROR, "DobbyCodePatch: both write paths failed for %p size=%u", address, buffer_size);
      return rc;
    }
  }

  // Critical on Android 16+: the write (via either path) removes EXEC
  // from the page's VMA. Re-add PROT_EXEC -- with memfd swap fallback
  // when MDWE blocks the mprotect.
  if (force_rx((void *)patch_page, page_size) != 0) {
    DOBBY_DIAG(ERROR,
               "DobbyCodePatch: patch bytes WERE written to %p, but the page "
               "could not be restored to R+X. Treating the patch as failed.",
               address);
    return -1;
  }
  if (patch_page != patch_end_page) {
    if (force_rx((void *)patch_end_page, page_size) != 0) {
      DOBBY_DIAG(ERROR,
                 "DobbyCodePatch: tail page 0x%lx (of patch at %p) could not "
                 "be restored to R+X.",
                 (unsigned long)patch_end_page, address);
      return -1;
    }
  }

  addr_t clear_start_ = (addr_t)address;
  ClearCache((void *)clear_start_, (void *)(clear_start_ + buffer_size));
#endif
  return 0;
}

#endif
