#ifndef NAGA_NAGA_NATIVE_H
#define NAGA_NAGA_NATIVE_H

#ifdef __cplusplus
#error NAGA_NATIVE_REQUIRES_C
#endif

#include "naga.h"

#if defined(_WIN32)
typedef uint16_t naga_path_char;
#else
typedef uint8_t naga_path_char;
#endif

typedef struct naga_native_error
{
    uint32_t code;
    char message[512];
} naga_native_error;

_Static_assert(sizeof(naga_native_error) == 516, "native error size");
_Static_assert(offsetof(naga_native_error, message) == 4, "native error message offset");

typedef struct naga_native_module naga_native_module;

void naga_native_initialize(void);
int32_t naga_native_directory(const naga_path_char*, size_t, naga_native_error*);
int32_t naga_native_library(const naga_path_char*, size_t, void**, naga_native_error*);
int32_t naga_native_bind(void*, const naga_host_api*, naga_bytes, naga_bytes, naga_native_module**, naga_native_error*);
void* naga_native_symbol(void*, const char*);
int32_t naga_native_start(naga_native_module*);
int32_t naga_native_stop(naga_native_module*);
int32_t naga_native_service(const naga_native_module*, naga_bytes, naga_bytes, naga_bytes, naga_output);
int32_t naga_native_event(naga_native_module*, naga_bytes, naga_bytes, naga_bytes);
void naga_native_release(naga_native_module*);
uint32_t naga_native_process_attach(uint64_t, uint32_t, uint64_t*);
uint32_t naga_native_process_terminate(uint64_t);

#endif
