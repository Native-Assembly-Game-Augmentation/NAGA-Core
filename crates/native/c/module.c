#include "naga_native.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct naga_native_module
{
    naga_module_api api;
    int started;
    int running;
    int stopped;
};

static int valid_bytes(const naga_bytes value)
{
    return value.len <= NAGA_MAX_ABI_BYTES && (value.len == 0 || value.data != NULL);
}

static int equal_bytes(const naga_bytes left, const naga_bytes right)
{
    return valid_bytes(left) && valid_bytes(right) && left.len == right.len && (left.len == 0 || memcmp(
        left.data, right.data, left.len) == 0);
}

static int32_t reject(naga_native_error* err, const int32_t status, const char* message)
{
    if (err != NULL)
    {
        err->code = (uint32_t)status;
        snprintf(err->message, sizeof(err->message), "%s", message);
    }

    return status;
}

int32_t naga_native_bind(void* library, const naga_host_api* host, const naga_bytes id, const naga_bytes version,
                         naga_native_module** output, naga_native_error* err)
{
    const naga_module_api* api = NULL;
    naga_native_module* module;
    naga_entry entry;

    int32_t status;

    if (output == NULL || host == NULL || host->struct_size < sizeof(*host) || !valid_bytes(id) || !valid_bytes(version))
        return reject(err, NAGA_INVALID_ARG, "invalid native host binding");

    *output = NULL;

    if (host->register_service == NULL || host->unregister_service == NULL || host->call_service == NULL
        || host->publish == NULL || host->subscribe == NULL || host->unsubscribe == NULL
        || host->diagnostic == NULL || host->configuration == NULL || host->package_root == NULL)
        return reject(err, NAGA_UNSUPPORTED, "native host ABI is incomplete");

    entry = (naga_entry)naga_native_symbol(library, "naga_entry_v1");
    if (entry == NULL)
        return reject(err, NAGA_UNSUPPORTED, "native module entry is missing");

    status = entry(host, &api);
    if (status != NAGA_OK || api == NULL)
        return reject(err, status == NAGA_OK ? NAGA_UNSUPPORTED : status, "native entry rejected host ABI");

    if (api->struct_size < sizeof(*api) || api->abi.major != host->abi.major || api->start == NULL || api->stop == NULL
        || api->service == NULL || api->event == NULL || api->destroy == NULL)
        return reject(err, NAGA_UNSUPPORTED, "native module ABI is incomplete or incompatible");

    if (!equal_bytes(api->module_id, id) || !equal_bytes(api->module_version, version))
        return reject(err, NAGA_UNSUPPORTED, "native module identity differs from manifest");

    module = calloc(1, sizeof(*module));
    if (module == NULL)
        return reject(err, NAGA_INTERNAL, "cannot allocate native module binding");
    module->api = *api;
    *output = module;
    return NAGA_OK;
}

int32_t naga_native_start(naga_native_module* module)
{
    int32_t status;
    if (module == NULL || module->started || module->stopped)
        return NAGA_BUSY;
    module->started = 1;
    status = module->api.start(module->api.context);
    module->running = status == NAGA_OK;
    return status;
}

int32_t naga_native_stop(naga_native_module* module)
{
    int32_t status;
    if (module == NULL || module->stopped)
        return NAGA_BUSY;

    module->stopped = 1;
    module->running = 0;
    status = module->api.stop(module->api.context);
    module->api.destroy(module->api.context);
    module->api.context = NULL;
    return status;
}

int32_t naga_native_service(const naga_native_module* module, const naga_bytes name, const naga_bytes operation,
                            const naga_bytes payload, const naga_output output)
{
    if (module == NULL || !module->running || module->stopped)
        return NAGA_UNAVAILABLE;

    if (!valid_bytes(name) || !valid_bytes(operation) || !valid_bytes(payload) || output.write == NULL)
        return NAGA_INVALID_ARG;

    return module->api.service(module->api.context, name, operation, payload, output);
}

int32_t naga_native_event(naga_native_module* module, const naga_bytes source, const naga_bytes topic, const naga_bytes payload)
{
    if (module == NULL || !module->running || module->stopped)
        return NAGA_UNAVAILABLE;

    if (!valid_bytes(source) || !valid_bytes(topic) || !valid_bytes(payload))
        return NAGA_INVALID_ARG;

    return module->api.event(module->api.context, source, topic, payload);
}

void naga_native_release(naga_native_module* module)
{
    free(module);
}
