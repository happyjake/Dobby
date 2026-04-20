
#include "dobby/dobby_internal.h"
#include "core/arch/Cpu.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

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

#if !defined(__APPLE__)

// On Android 16+ W^X is strictly enforced. Two related traps:
//
// 1) mprotect(PROT_READ|PROT_WRITE|PROT_EXEC) silently drops EXEC (or fails
//    with EACCES), leaving the page RW-only. memcpy then succeeds but
//    CPU branches into the page SIGSEGV with SEGV_ACCERR.
//
// 2) Writing to an executable page via /proc/self/mem bypasses VMA
//    protection checks but the kernel still strips PROT_EXEC from the
//    VMA as part of the write (COW on file-backed executable mappings).
//    The written code is correct but the page is no longer executable.
//
// Fix strategy (sequential W -> X transitions are allowed; only
// simultaneous W+X is forbidden):
//   a) Ensure the page is writable: mprotect(R+W), or rely on
//      /proc/self/mem's COW-and-write which accomplishes the same.
//   b) memcpy / pwrite the new bytes.
//   c) Restore PROT_READ|PROT_EXEC. Required whether we used
//      mprotect or /proc/self/mem -- both paths leave the VMA in a
//      non-executable state on A16+.
//
// Observed on nezha / Android 16 (kernel 6.12): step (c) *silently fails*
// in the zygote-child context, leaving libart code pages RW. Every
// subsequent indirect call into the page faults with SEGV_ACCERR
// ("trying to execute non-executable memory"). We now check the return
// value and log errno so the root cause is visible instead of a
// mysterious SetStatus+0 tombstone minutes later.

static int force_rx(void *page, size_t size) {
  int r = mprotect(page, size, PROT_READ | PROT_EXEC);
  if (r != 0) {
    int err = errno;
    DOBBY_DIAG(ERROR,
               "force_rx mprotect(R+X) FAILED: page=%p size=%zu errno=%d (%s)",
               page, size, err, strerror(err));
    errno = err;
  } else {
    DOBBY_DIAG(INFO, "force_rx(R+X) ok: page=%p size=%zu", page, size);
  }
  return r;
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

  // Primary: /proc/self/mem, protection-agnostic write
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
  // from the page's VMA. Re-add PROT_EXEC so future calls into this
  // address don't SIGSEGV with "trying to execute non-executable memory".
  if (force_rx((void *)patch_page, page_size) != 0) {
    DOBBY_DIAG(ERROR,
               "DobbyCodePatch: patch bytes WERE written to %p, but the page "
               "could not be restored to R+X. The caller's hook WILL crash on "
               "next invocation. Treating the patch as failed.",
               address);
    return -1;
  }
  if (patch_page != patch_end_page) {
    if (force_rx((void *)patch_end_page, page_size) != 0) {
      DOBBY_DIAG(ERROR,
                 "DobbyCodePatch: tail page 0x%lx (of patch at %p) could not be "
                 "restored to R+X.",
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
