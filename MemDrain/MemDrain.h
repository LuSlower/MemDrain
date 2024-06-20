#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

typedef struct _MEMORY_COMBINE_INFORMATION_EX {
    HANDLE Handle;
    ULONG_PTR PagesCombined;
    ULONG Flags;
} MEMORY_COMBINE_INFORMATION_EX, *PMEMORY_COMBINE_INFORMATION_EX;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
	MemoryCaptureAccessedBits,
	MemoryCaptureAndResetAccessedBits,
	MemoryEmptyWorkingSets,
	MemoryFlushModifiedList,
	MemoryPurgeStandbyList,
	MemoryPurgeLowPriorityStandbyList,
	MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;


// definicion de SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS_MOD {
    SystemCombinePhysicalMemoryInformation = 130,
    SystemFileCacheInformationEx = 81,
    SystemMemoryListInformation = 80,
    SystemRegistryReconciliationInformation = 155,
} SYSTEM_INFORMATION_CLASS_MOD;

extern "C"{
typedef NTSTATUS LONG;
// Definir funciones internas
NTSYSAPI
NTSTATUS
NTAPI
NtSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS_MOD SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength
);
}

DWORD GetChildProcesses(DWORD ParentPID, DWORD* ChildPIDs) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error al crear un snapshot de procesos");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    DWORD NumProcesses = 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ParentProcessID == ParentPID) {
                if (NumProcesses < 64) {
                    ChildPIDs[NumProcesses++] = pe32.th32ProcessID;
                } else {
                    printf("Se alcanzó el límite máximo de procesos hijos");
                    break;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return NumProcesses;
}

DWORD GetPID(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Error al crear un snapshot de procesos");
        return 0;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        printf("Error al obtener la primera entrada de proceso");
        return 0;
    }

    DWORD processId = 0;
    do {
        if (strcmp(entry.szExeFile, processName) == 0) {
            processId = entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return processId;
}

bool EnablePrivilege(DWORD processId, LPCSTR privilegeName, HANDLE hProcess = NULL) {

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, privilegeName, &tp.Privileges[0].Luid)) {
        printf("Error al buscar el valor del privilegio ");
        return false;
    }

    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        // comprobar por ultima vez
        if (!hProcess){
        printf("Error al abrir el token del proceso");
        return false;
        }
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
        printf("Error al abrir el token del proceso");
        CloseHandle(hProcess);
        return false;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Error al ajustar los privilegios del token");
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}

