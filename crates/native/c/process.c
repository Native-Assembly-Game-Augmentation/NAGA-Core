#include "naga_native.h"
#include <limits.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif

uint32_t naga_native_process_attach(const uint64_t process, const uint32_t pid, uint64_t* output)
{
    if (output == NULL || pid == 0)
    {
#if defined(_WIN32)
        return ERROR_INVALID_PARAMETER;
#else
        return EINVAL;
#endif
    }
    *output = 0;
#if defined(_WIN32)
    HANDLE job;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    (void)pid;

    if (process == 0) return ERROR_INVALID_HANDLE;

    job = CreateJobObjectW(NULL, NULL);
    if (job == NULL)
        return GetLastError();

    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))
        || !AssignProcessToJobObject(job, (HANDLE)(uintptr_t)process))
    {
        const uint32_t code = GetLastError();
        CloseHandle(job);
        return code;
    }
    *output = (uint64_t)(uintptr_t)job;
#else
    (void)process;
    if (pid > INT_MAX || getpgid((pid_t)pid) != (pid_t)pid)
        return EINVAL;
    *output = pid;
#endif
    return 0;
}

uint32_t naga_native_process_terminate(const uint64_t tree)
{
    if (tree == 0) return 0;
#if defined(_WIN32)
    if (!CloseHandle((HANDLE)(uintptr_t)tree)) return GetLastError();
#else
    if (tree > INT_MAX) return EINVAL;

    if (kill(-(pid_t)tree, SIGKILL) != 0 && errno != ESRCH)
        return (uint32_t)errno;
#endif
    return 0;
}
