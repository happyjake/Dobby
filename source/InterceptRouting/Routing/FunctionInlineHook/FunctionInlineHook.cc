#include "dobby/dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHookRouting.h"

#if defined(__ANDROID__)
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#define PROBE_LOG(lvl, fmt, ...) \
  __android_log_print(ANDROID_LOG_##lvl, "Dobby-probe", fmt, ##__VA_ARGS__)

// Run once per process at first DobbyHook. Reproduces the exact operations
// DobbyCodePatch does against a libart-like target, and logs the outcome.
// Goal: confirm whether mmap(MAP_FIXED, R+X, memfd) is denied in the real
// zygote-child context even though the same call succeeds in a shell exec.
static void dobby_mdwe_probe_once() {
  static bool ran = false;
  if (ran) return;
  ran = true;

  const size_t PG = 4096;

  // [1] anon R+X mmap (fresh) -- baseline, should always work.
  void *anon = mmap(nullptr, PG, PROT_READ | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (anon == MAP_FAILED) {
    PROBE_LOG(ERROR, "[1] mmap(R+X, ANON) FAIL errno=%d (%s)",
              errno, strerror(errno));
  } else {
    PROBE_LOG(INFO, "[1] mmap(R+X, ANON) ok @ %p", anon);
  }

  // [2] memfd R+X + mmap -- fresh R+X file-backed from memfd.
  int mfd = (int)syscall(__NR_memfd_create, "dobby-probe",
                         MFD_EXEC | MFD_CLOEXEC);
  if (mfd < 0) {
    int e = errno;
    mfd = (int)syscall(__NR_memfd_create, "dobby-probe", MFD_CLOEXEC);
    PROBE_LOG(WARN, "[2] memfd_create MFD_EXEC failed errno=%d (%s); "
                    "fallback mfd=%d errno=%d",
              e, strerror(e), mfd, errno);
  }
  void *memfd_map = MAP_FAILED;
  if (mfd >= 0) {
    uint8_t zero[4096] = {0};
    ftruncate(mfd, PG);
    write(mfd, zero, PG);
    memfd_map = mmap(nullptr, PG, PROT_READ | PROT_EXEC, MAP_PRIVATE, mfd, 0);
    if (memfd_map == MAP_FAILED) {
      PROBE_LOG(ERROR, "[2] mmap(R+X, memfd fresh) FAIL errno=%d (%s)",
                errno, strerror(errno));
    } else {
      PROBE_LOG(INFO, "[2] mmap(R+X, memfd fresh) ok @ %p", memfd_map);
    }
  }

  // [3] MAP_FIXED memfd R+X over anon R+X target -- our baseline that was
  // known to work in shell.
  if (anon != MAP_FAILED && mfd >= 0) {
    void *r = mmap(anon, PG, PROT_READ | PROT_EXEC,
                   MAP_PRIVATE | MAP_FIXED, mfd, 0);
    if (r == MAP_FAILED) {
      PROBE_LOG(ERROR, "[3] MAP_FIXED memfd R+X over anon R+X FAIL errno=%d (%s)",
                errno, strerror(errno));
    } else {
      PROBE_LOG(INFO, "[3] MAP_FIXED memfd R+X over anon R+X ok");
    }
  }

  // [4] The REAL case: MAP_FIXED memfd R+X over a file-backed libart page.
  // Open libart.so, mmap one page R+X (this mimics what the dynamic linker
  // did for the process's real libart), then try to MAP_FIXED swap it.
  int art_fd = open("/apex/com.android.art/lib64/libart.so", O_RDONLY | O_CLOEXEC);
  if (art_fd < 0) {
    PROBE_LOG(WARN, "[4] open(libart.so) failed errno=%d (%s); trying libc",
              errno, strerror(errno));
    art_fd = open("/apex/com.android.runtime/lib64/bionic/libc.so", O_RDONLY | O_CLOEXEC);
  }
  if (art_fd >= 0 && mfd >= 0) {
    // Map the code section offset (libart has r-x at ~0x200000 offset per tombstones).
    off_t file_off = 0x200000;
    void *filemap = mmap(nullptr, PG, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE, art_fd, file_off);
    if (filemap == MAP_FAILED) {
      // Offset may be outside range for libc; retry at 0.
      filemap = mmap(nullptr, PG, PROT_READ | PROT_EXEC,
                     MAP_PRIVATE, art_fd, 0);
    }
    if (filemap == MAP_FAILED) {
      PROBE_LOG(ERROR, "[4a] mmap(R+X, file libart) FAIL errno=%d (%s)",
                errno, strerror(errno));
    } else {
      PROBE_LOG(INFO, "[4a] mmap(R+X, file libart) ok @ %p", filemap);
      void *r = mmap(filemap, PG, PROT_READ | PROT_EXEC,
                     MAP_PRIVATE | MAP_FIXED, mfd, 0);
      if (r == MAP_FAILED) {
        PROBE_LOG(ERROR,
                  "[4b] MAP_FIXED memfd R+X over FILE R+X FAIL errno=%d (%s) "
                  "<-- this is the failure we need to explain",
                  errno, strerror(errno));
      } else {
        PROBE_LOG(INFO,
                  "[4b] MAP_FIXED memfd R+X over FILE R+X ok -- bug is "
                  "elsewhere, real failure must depend on VMA history");
      }
      munmap(filemap, PG);
    }
  }

  // [5] MAP_FIXED anon R+X over file-backed R+X target (isolates memfd
  // vs anon as replacement).
  if (art_fd >= 0) {
    void *filemap = mmap(nullptr, PG, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE, art_fd, 0);
    if (filemap != MAP_FAILED) {
      void *r = mmap(filemap, PG, PROT_READ | PROT_EXEC,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
      if (r == MAP_FAILED) {
        PROBE_LOG(ERROR, "[5] MAP_FIXED anon R+X over FILE R+X FAIL errno=%d (%s)",
                  errno, strerror(errno));
      } else {
        PROBE_LOG(INFO, "[5] MAP_FIXED anon R+X over FILE R+X ok");
      }
      munmap(filemap, PG);
    }
  }

  // [6] Try patching the PROCESS'S OWN LIBART in place (the real target).
  // Find a libart r-x page via /proc/self/maps and attempt MAP_FIXED over it.
  FILE *f = fopen("/proc/self/maps", "re");
  uintptr_t real_libart_page = 0;
  if (f) {
    char line[512];
    while (fgets(line, sizeof(line), f)) {
      unsigned long s, e;
      char perms[5];
      if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) == 3 &&
          perms[2] == 'x' && strstr(line, "libart.so")) {
        real_libart_page = s;
        break;
      }
    }
    fclose(f);
  }
  if (real_libart_page && mfd >= 0) {
    PROBE_LOG(INFO, "[6] real libart r-x page found at 0x%lx — attempting swap",
              (unsigned long)real_libart_page);
    // Snapshot page first, put into memfd at offset 0.
    uint8_t snap[4096];
    memcpy(snap, (void *)real_libart_page, PG);
    lseek(mfd, 0, SEEK_SET);
    write(mfd, snap, PG);
    void *r = mmap((void *)real_libart_page, PG, PROT_READ | PROT_EXEC,
                   MAP_PRIVATE | MAP_FIXED, mfd, 0);
    if (r == MAP_FAILED) {
      PROBE_LOG(ERROR,
                "[6] MAP_FIXED over REAL libart r-x page FAIL errno=%d (%s) "
                "<-- reproduces the bug",
                errno, strerror(errno));
    } else {
      PROBE_LOG(INFO, "[6] MAP_FIXED over REAL libart r-x page OK -- "
                      "unexpected, bug must be elsewhere");
    }
    // Do NOT un-swap; process is about to exit after probe or continue with
    // identical bytes -- no functional change.
  }

  if (anon != MAP_FAILED) munmap(anon, PG);
  if (memfd_map != MAP_FAILED) munmap(memfd_map, PG);
  if (mfd >= 0) close(mfd);
  if (art_fd >= 0) close(art_fd);
  PROBE_LOG(INFO, "[probe] done");
}
#define RUN_MDWE_PROBE() dobby_mdwe_probe_once()
#else
#define RUN_MDWE_PROBE() ((void)0)
#endif

PUBLIC int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func) {
  RUN_MDWE_PROBE();
  if (!address) {
    ERROR_LOG("function address is 0x0");
    return -1;
  }

#if defined(__APPLE__) && defined(__arm64__)
  address = pac_strip(address);
  replace_func = pac_strip(replace_func);
#endif

#if defined(ANDROID)
  void *page_align_address = (void *)ALIGN_FLOOR(address, OSMemory::PageSize());
  if (!OSMemory::SetPermission(page_align_address, OSMemory::PageSize(), kReadExecute)) {
    return -1;
  }
#endif

  DEBUG_LOG("----- [DobbyHook:%p] -----", address);

  // check if already register
  auto entry = Interceptor::SharedInstance()->find((addr_t)address);
  if (entry) {
    ERROR_LOG("%p already been hooked.", address);
    return -1;
  }

  entry = new InterceptEntry(kFunctionInlineHook, (addr_t)address);

  auto *routing = new FunctionInlineHookRouting(entry, replace_func);
  routing->Prepare();
  routing->DispatchRouting();

  // set origin func entry with as relocated instructions
  if (origin_func) {
    *origin_func = (dobby_dummy_func_t)entry->relocated_addr;
#if defined(__APPLE__) && defined(__arm64__)
    *origin_func = pac_sign(*origin_func);
#endif
  }

  routing->Commit();

  Interceptor::SharedInstance()->add(entry);

  return 0;
}
