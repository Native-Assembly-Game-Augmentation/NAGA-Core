#include "naga.h"

_Static_assert(sizeof(naga_abi_version) == 12, "ABI version size");
_Static_assert(sizeof(naga_bytes) == 16, "borrowed buffer size");
_Static_assert(sizeof(naga_output) == 16, "output size");
_Static_assert(sizeof(naga_host_api) == 96, "host API size");
_Static_assert(sizeof(naga_module_api) == 96, "module API size");
_Static_assert(offsetof(naga_host_api, context) == 16, "host context offset");
_Static_assert(offsetof(naga_module_api, module_id) == 16, "module identity offset");
_Static_assert(NAGA_OK == 0 && NAGA_INVALID_ARG == 1 && NAGA_UNSUPPORTED == 2, "argument status values");
_Static_assert(NAGA_INTERNAL == 3 && NAGA_UNAVAILABLE == 4 && NAGA_TIMEOUT == 5, "runtime status values");
_Static_assert(NAGA_DEPENDENCY_DENIED == 6 && NAGA_BUSY == 7 && NAGA_PANIC == 8, "lifecycle status values");
