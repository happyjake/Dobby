#include "logging/logging.h"

#include "TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.h"

#if defined(__ANDROID__)
#include <android/log.h>
#define DOBBY_DIAG_BRIDGE(fmt, ...) \
  __android_log_print(ANDROID_LOG_INFO, "Dobby-bridge", fmt, ##__VA_ARGS__)
#else
#define DOBBY_DIAG_BRIDGE(fmt, ...) ((void)0)
#endif

PUBLIC void common_closure_bridge_handler(DobbyRegisterContext *ctx, ClosureTrampolineEntry *entry) {
  DOBBY_DIAG_BRIDGE(
      "common_bridge_handler entry=%p data=%p handler=%p",
      entry, entry ? entry->carry_data : nullptr,
      entry ? entry->carry_handler : nullptr);
  DEBUG_LOG("common bridge handler: carry data: %p, carry handler: %p", (InterceptEntry *)entry->carry_data,
            entry->carry_handler);

  typedef void (*routing_handler_t)(InterceptEntry *, DobbyRegisterContext *);
  auto routing_handler = (routing_handler_t)entry->carry_handler;

#if defined(__APPLE__) && __arm64e__
#if __has_feature(ptrauth_calls)
  uint64_t discriminator = 0;
  // discriminator = __builtin_ptrauth_type_discriminator(__typeof(routing_handler));
  routing_handler = (__typeof(routing_handler))__builtin_ptrauth_sign_unauthenticated((void *)routing_handler,
                                                                                      ptrauth_key_asia, discriminator);
#endif
#endif

  routing_handler((InterceptEntry *)entry->carry_data, ctx);
}
