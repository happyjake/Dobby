#include "dobby/dobby_internal.h"

#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"

#if defined(__ANDROID__)
#include <android/log.h>
#define DOBBY_DIAG_HOOK(fmt, ...) \
  __android_log_print(ANDROID_LOG_INFO, "Dobby-hook", fmt, ##__VA_ARGS__)
#else
#define DOBBY_DIAG_HOOK(fmt, ...) ((void)0)
#endif

using namespace zz;

void log_hex_format(uint8_t *buffer, uint32_t buffer_size) {
#if !defined(DOBBY_LOGGING_DISABLE)
  // Only do the strlen/snprintf loop when logging will actually emit.
  // The loop has observable side effects (snprintf), so the compiler
  // can't dead-code-eliminate it even though the output buffer is
  // thrown away -- and on A16+ callers sometimes pass addresses that
  // live inside guard pages (stale symbol cache, mis-resolved
  // ArtMethod entry_point_from_quick_compiled_code_, etc.), which
  // SIGSEGVs the first `*buffer` read. Guard it here.
  char output[1024] = {0};
  for (int i = 0; i < buffer_size && i < sizeof(output); i++) {
    snprintf(output + strlen(output), 3, "%02x", *((uint8_t *)buffer + i));
  }
  DEBUG_LOG("%s", output);
#else
  (void)buffer;
  (void)buffer_size;
#endif
};

void InterceptRouting::Prepare() {
}

// generate relocated code
bool InterceptRouting::GenerateRelocatedCode() {
  uint32_t tramp_size = GetTrampolineBuffer()->GetBufferSize();
  origin_ = new CodeMemBlock(entry_->patched_addr, tramp_size);
  relocated_ = new CodeMemBlock();

  auto buffer = (void *)entry_->patched_addr;
#if defined(TARGET_ARCH_ARM)
  if (entry_->thumb_mode) {
    buffer = (void *)((addr_t)buffer + 1);
  }
#endif
  GenRelocateCodeAndBranch(buffer, origin_, relocated_);
  if (relocated_->size == 0) {
    ERROR_LOG("[insn relocate]] failed");
    return false;
  }

  // set the relocated instruction address
  entry_->relocated_addr = relocated_->addr;

  // save original prologue
  memcpy((void *)entry_->origin_insns, (void *)origin_->addr, origin_->size);
  entry_->origin_insn_size = origin_->size;

  // log
  DEBUG_LOG("[insn relocate] origin %p - %d", origin_->addr, origin_->size);
  log_hex_format((uint8_t *)origin_->addr, origin_->size);

  DEBUG_LOG("[insn relocate] relocated %p - %d", relocated_->addr, relocated_->size);
  log_hex_format((uint8_t *)relocated_->addr, relocated_->size);

  return true;
}

bool InterceptRouting::GenerateTrampolineBuffer(addr_t src, addr_t dst) {
  // if near branch trampoline plugin enabled
  if (RoutingPluginManager::near_branch_trampoline) {
    auto plugin = static_cast<RoutingPluginInterface *>(RoutingPluginManager::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DEBUG_LOG("Failed enable near branch trampoline plugin");
    }
  }

  if (GetTrampolineBuffer() == nullptr) {
    auto tramp_buffer = GenerateNormalTrampolineBuffer(src, dst);
    SetTrampolineBuffer(tramp_buffer);
  }
  return true;
}

// active routing, patch origin instructions as trampoline
void InterceptRouting::Active() {
  DOBBY_DIAG_HOOK("Active target=0x%lx tramp_size=%zu",
                  (unsigned long)entry_->patched_addr,
                  (size_t)trampoline_buffer_->GetBufferSize());
  auto ret = DobbyCodePatch((void *)entry_->patched_addr, trampoline_buffer_->GetBuffer(),
                            trampoline_buffer_->GetBufferSize());
  if (ret == -1) {
    DOBBY_DIAG_HOOK("Active FAILED target=0x%lx",
                    (unsigned long)entry_->patched_addr);
    ERROR_LOG("[intercept routing] active failed");
    return;
  }
  DOBBY_DIAG_HOOK("Active OK target=0x%lx relocated=0x%lx",
                  (unsigned long)entry_->patched_addr,
                  (unsigned long)entry_->relocated_addr);
  DEBUG_LOG("[intercept routing] active");
}

void InterceptRouting::Commit() {
  this->Active();
}

#if 0
int InterceptRouting::PredefinedTrampolineSize() {
#if __arm64__
  return 12;
#elif __arm__
  return 8;
#endif
}
#endif

InterceptEntry *InterceptRouting::GetInterceptEntry() {
  return entry_;
};
