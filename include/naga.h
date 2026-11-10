#ifndef NAGA_ABI_V1_H
#define NAGA_ABI_V1_H

#include <stddef.h>
#include <stdint.h>

#define NAGA_MAX_ABI_BYTES ((size_t) 8388608)

#if INTPTR_MAX != INT64_MAX
#error NAGA_ABI_V1_REQUIRES_64_BIT_POINTERS
#endif

#ifdef __cplusplus
extern "C"
{
#endif

enum naga_status
{
    NAGA_OK = 0,
    NAGA_INVALID_ARG = 1,
    NAGA_UNSUPPORTED = 2,
    NAGA_INTERNAL = 3,
    NAGA_UNAVAILABLE = 4,
    NAGA_TIMEOUT = 5,
    NAGA_DEPENDENCY_DENIED = 6,
    NAGA_BUSY = 7,
    NAGA_PANIC = 8
};

typedef struct naga_abi_version
{
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
} naga_abi_version;

typedef struct naga_bytes
{
    const uint8_t* data;
    size_t len;
} naga_bytes;

typedef struct naga_output
{
    void* context;
    int32_t (*write)(void*, naga_bytes);
} naga_output;

typedef struct naga_host_api
{
    uint32_t struct_size;
    naga_abi_version abi;
    void* context;
    int32_t (*register_service)(void*, naga_bytes, naga_bytes);
    int32_t (*unregister_service)(void*, naga_bytes, naga_bytes);
    int32_t (*call_service)(void*, naga_bytes, naga_bytes, naga_bytes, naga_bytes, naga_output);
    int32_t (*publish)(void*, naga_bytes, naga_bytes);
    int32_t (*subscribe)(void*, naga_bytes);
    int32_t (*unsubscribe)(void*, naga_bytes);
    int32_t (*diagnostic)(void*, uint32_t, naga_bytes);
    int32_t (*configuration)(void*, naga_output);
    int32_t (*package_root)(void*, naga_output);
} naga_host_api;

typedef struct naga_module_api
{
    uint32_t struct_size;
    naga_abi_version abi;
    naga_bytes module_id;
    naga_bytes module_version;
    void* context;
    int32_t (*start)(void*);
    int32_t (*stop)(void*);
    int32_t (*service)(void*, naga_bytes, naga_bytes, naga_bytes, naga_output);
    int32_t (*event)(void*, naga_bytes, naga_bytes, naga_bytes);
    void (*destroy)(void*);
} naga_module_api;

typedef int32_t (*naga_entry)(const naga_host_api*, const naga_module_api**);

#ifdef __cplusplus
}
#endif

#endif
