#include "naga_native.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

static int32_t failure(naga_native_error* err, const uint32_t code, const char* message)
{
    if (err != NULL)
    {
        err->code = code;
        snprintf(err->message, sizeof(err->message), "%s", message);
    }

    return NAGA_UNAVAILABLE;
}

static naga_path_char* copy_path(const naga_path_char* path, const size_t length)
{
    naga_path_char* copy;

    if (path == NULL || length == 0 || length > 32767)
        return NULL;

    for (size_t index = 0; index < length; index++)
    {
        if (path[index] == 0) return NULL;
    }

    copy = calloc(length + 1, sizeof(*copy));

    if (copy != NULL)
        memcpy(copy, path, length * sizeof(*copy));

    return copy;
}

void naga_native_initialize(void)
{
#if defined(_WIN32)
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#endif
}

int32_t naga_native_directory(const naga_path_char* path, const size_t length, naga_native_error* err)
{
    naga_path_char* copy = copy_path(path, length);
    if (copy == NULL) return failure(err, 0, "invalid native library directory");
#if defined(_WIN32)
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32))
    {
        const uint32_t code = GetLastError();
        free(copy);
        return failure(err, code, "cannot configure native library search");
    }

    if (AddDllDirectory(copy) == NULL)
    {
        const uint32_t code = GetLastError();
        free(copy);
        return failure(err, code, "cannot register native library directory");
    }

#else
    (void)err;
#endif
    free(copy);
    return NAGA_OK;
}

int32_t naga_native_library(const naga_path_char* path, const size_t length, void** output, naga_native_error* err)
{
    naga_path_char* copy;
    void* library;
    if (output == NULL) return failure(err, 0, "missing library output");

    *output = NULL;
    copy = copy_path(path, length);
    if (copy == NULL)
        return failure(err, 0, "invalid native library path");
#if defined(_WIN32)
    library = LoadLibraryExW
    (
        copy, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32
    );

    const uint32_t load_err = library == NULL ? GetLastError() : 0;
    free(copy);

    if (library == NULL) return failure(err, load_err, "cannot load native library");

    {
        HMODULE pinned = NULL;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, library, &pinned))
            return failure(err, GetLastError(), "cannot pin native library for process lifetime");
    }
#else
    library = dlopen((const char*)copy, RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
    free(copy);
    if (library == NULL) return failure(err, 0, dlerror());
#endif
    *output = library;
    return NAGA_OK;
}

void* naga_native_symbol(void* library, const char* name)
{
    if (library == NULL || name == NULL)
        return NULL;

#if defined(_WIN32)
    return (void*)GetProcAddress(library, name);
#else
    return dlsym(library, name);
#endif
}
