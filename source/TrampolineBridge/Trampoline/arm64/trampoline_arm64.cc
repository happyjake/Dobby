#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_ARM64)

#include "dobby/dobby_internal.h"

#include "core/assembler/assembler-arm64.h"
#include "core/codegen/codegen-arm64.h"

#include "MemoryAllocator/NearMemoryAllocator.h"
#include "InstructionRelocation/arm64/InstructionRelocationARM64.h"
#include "InterceptRouting/RoutingPlugin/RoutingPlugin.h"

using namespace zz::arm64;

CodeBufferBase *GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
  TurboAssembler turbo_assembler_((void *)from);
#define _ turbo_assembler_.

  // ARMv9 Branch Target Identification (BTI).
  //
  // Libraries built with -mbranch-protection=standard (e.g. libart.so on
  // Android 14+) have .note.gnu.property advertising BTI, so bionic maps
  // their code pages with PROT_BTI. On BTI-guarded pages an indirect branch
  // (BLR / BR) must land on a `bti` / `paciasp` instruction; landing
  // anywhere else raises a Branch Target Exception, delivered as SIGSEGV /
  // SEGV_ACCERR -- indistinguishable from "trying to execute non-executable
  // memory" in Android tombstones.
  //
  // When Dobby overwrites the first instructions of a hooked function, the
  // replacement is `adrp/add/br` or `ldr/br/<addr>` -- neither is a landing
  // pad. Any subsequent indirect call to the hooked function (virtual
  // dispatch, JNIEnv vtable, ArtMethod entrypoint, C++ PMF, etc.) BTI-faults.
  //
  // Prepend `bti jc` (0xD50324DF, HINT #0x26) so both BR and BLR targets
  // remain legal. It is a NOP on pre-Armv8.5 CPUs, so this is always safe.
  // The adrp / ldr offsets below are PC-relative and re-anchor to the new
  // PC after the hint, so no other math has to change.
  _ Emit(0xD50324DFu); // bti jc (accepts both BR and BLR indirect branches)

  uint64_t distance = llabs((int64_t)(from - to));
  uint64_t adrp_range = ((uint64_t)1 << (2 + 19 + 12 - 1));
  if (distance < adrp_range) {
    // bti jc, adrp, add, br
    _ AdrpAdd(TMP_REG_0, from + 4, to);
    _ br(TMP_REG_0);
    DEBUG_LOG("[trampoline] use [bti jc, adrp, add, br]");
  } else {
    // bti jc, ldr, br, branch-address
    CodeGen codegen(&turbo_assembler_);
    codegen.LiteralLdrBranch((uint64_t)to);
    DEBUG_LOG("[trampoline] use [bti jc, ldr, br, #label]");
  }
#undef _

  // Bind all labels
  turbo_assembler_.RelocBind();

  auto result = turbo_assembler_.GetCodeBuffer()->Copy();
  return result;
}

#endif
