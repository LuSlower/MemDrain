#include "MemDrain.h"

// Definir una estructura para asociar opciones con funciones
typedef struct {
    const char* option;
    void (*action)(int argc, char* argv[]);
} OptionAction;

// Funciones para cada accion
void help_action(int argc, char* argv[]) {
    printf("use: md.exe <Argument> <Parameter>\n");
    printf("\n  -ws <IM> <-r>   |   Drain WorkingSet");
    printf("\n  -sws            |   Drain SystemWorkingSet");
    printf("\n  -mpl            |   Drain ModifiedPageList");
    printf("\n  -mcl            |   Drain CombineMemoryList");
    printf("\n  -sl <0>         |   Drain StanbyList (and low priority)");
    printf("\n  -rh             |   Drain Registry Hives");
    printf("\n  -all            |   Drain All");

}
void working_set_action(int argc, char* argv[]){

    // Verificar parametros adicionales
    if (argc >= 3){
        //obtener PID
        DWORD PID = GetPID(argv[2]);
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, FALSE, PID);
        EmptyWorkingSet(hProcess);
        // Establecerlo en todos los procesos hijos
        if (argc == 4 && strcmp(argv[3], "-r") == 0){
            DWORD ChildPIDs[64] = {0};
            DWORD NumProcesses = GetChildProcesses(PID, ChildPIDs);

            for (DWORD i = 0; i < NumProcesses; i++) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, FALSE, ChildPIDs[i]);
                EmptyWorkingSet(hProcess);
                CloseHandle(hProcess);
            }
        }
        CloseHandle(hProcess);
        printf("Sucess");
        return;
    }

    // Habilitar privilegio
    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    // Liberar todo el conjunto de trabajo de la memoria
    SYSTEM_MEMORY_LIST_COMMAND ws;
    ws = MemoryEmptyWorkingSets;
    NtSetSystemInformation(SystemMemoryListInformation, &ws, sizeof(ws));
    printf("Sucess");
    return;
}

void system_working_set_action(int argc, char* argv[]){

    // Habilitar privilegio
    EnablePrivilege(GetCurrentProcessId(), SE_INCREASE_QUOTA_NAME);

    // Liberar System WS
    SYSTEM_FILECACHE_INFORMATION sfi;
    SecureZeroMemory(&sfi, sizeof(sfi));
    sfi.Flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE;
    sfi.MaximumWorkingSet = (SIZE_T) -1;
    sfi.MinimumWorkingSet = (SIZE_T) -1;
    NtSetSystemInformation(SystemFileCacheInformationEx, &sfi, sizeof(sfi));
    printf("Sucess");
    return;
}

void modified_page_list_action(int argc, char* argv[]){

    //Habilitar privilegio
    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    // Liberar lista de paginas modificadas
    SYSTEM_MEMORY_LIST_COMMAND mpl;
    mpl = MemoryFlushModifiedList;
    NtSetSystemInformation(SystemMemoryListInformation, &mpl, sizeof(mpl));
    printf("Sucess");
    return;

}

void combine_memory_list_action(int argc, char* argv[]){

    //Habilitar privilegio
    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    // Liberar lista de paginas combinadas
    MEMORY_COMBINE_INFORMATION_EX mcl;
    SecureZeroMemory(&mcl, sizeof(mcl));
    mcl.Handle = NULL;
    mcl.Flags = 0;
    mcl.PagesCombined = 0;
    NtSetSystemInformation (SystemCombinePhysicalMemoryInformation, &mcl, sizeof(mcl));
    printf("Sucess");
    return;
}

void stanby_list_action(int argc, char* argv[]){

    //Habilitar privilegio
    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    // Liberar lista de espera
    SYSTEM_MEMORY_LIST_COMMAND sl;
    sl = MemoryPurgeStandbyList;
    NtSetSystemInformation(SystemMemoryListInformation, &sl, sizeof(sl));
    if (argc > 2){
        // Liberar lista de espera de baja prioridad
        SYSTEM_MEMORY_LIST_COMMAND sl0;
        sl0 = MemoryPurgeLowPriorityStandbyList;
        NtSetSystemInformation(SystemMemoryListInformation, &sl0, sizeof(sl0));
    }
    printf("Sucess");
    return;


}

void registry_hives_action(int argc, char* argv[]){
    // Vaciar colmenas (hives) de registro
    NtSetSystemInformation (SystemRegistryReconciliationInformation, NULL, 0);
    printf("Sucess");
    return;
}

void all_action(int argc, char* argv[]){

    // Habilitar privilegio
    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);
    EnablePrivilege(GetCurrentProcessId(), SE_INCREASE_QUOTA_NAME);

    // Liberar todo el conjunto de trabajo de la memoria
    SYSTEM_MEMORY_LIST_COMMAND ws;
    ws = MemoryEmptyWorkingSets;
    NtSetSystemInformation(SystemMemoryListInformation, &ws, sizeof(ws));

    // Liberar System WS
    _SYSTEM_FILECACHE_INFORMATION sfi;
    SecureZeroMemory(&sfi, sizeof(sfi));
    sfi.Flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE;
    sfi.MaximumWorkingSet = (SIZE_T) -1;
    sfi.MinimumWorkingSet = (SIZE_T) -1;
    NtSetSystemInformation (SystemFileCacheInformationEx, &sfi, sizeof (sfi));

    // Liberar lista de paginas modificadas
    SYSTEM_MEMORY_LIST_COMMAND mpl;
    mpl = MemoryFlushModifiedList;
    NtSetSystemInformation(SystemMemoryListInformation, &mpl, sizeof(mpl));

    // Liberar lista de paginas combinadas
    _MEMORY_COMBINE_INFORMATION_EX mcl;
    SecureZeroMemory(&mcl, sizeof(mcl));
    mcl.Handle = NULL;
    mcl.Flags = 0;
    mcl.PagesCombined = 0;
    NtSetSystemInformation (SystemCombinePhysicalMemoryInformation, &mcl, sizeof(mcl));

    // Liberar lista de espera
    SYSTEM_MEMORY_LIST_COMMAND sl;
    sl = MemoryPurgeStandbyList;
    NtSetSystemInformation(SystemMemoryListInformation, &sl, sizeof(sl));

    // Liberar lista de espera de baja prioridad
    SYSTEM_MEMORY_LIST_COMMAND sl0;
    sl0 = MemoryPurgeLowPriorityStandbyList;
    NtSetSystemInformation(SystemMemoryListInformation, &sl0, sizeof(sl0));

    // Vaciar colmenas (hives) de registro
    NtSetSystemInformation (SystemRegistryReconciliationInformation, NULL, 0);

    printf("Sucess");
    return;

}

// Definir las opciones y las funciones asociadas
OptionAction option_actions[] = {
    {"help", help_action},
    {"-ws", working_set_action},
    {"-sws", system_working_set_action},
    {"-mpl", modified_page_list_action},
    {"-mcl", combine_memory_list_action},
    {"-sl", stanby_list_action},
    {"-rh", registry_hives_action},
    {"-all", all_action},
    {NULL, NULL} // ultimo elemento
};

//buscar parametro que coincida
int main(int argc, char* argv[]) {

    if (argc < 2) {
        help_action(argc, argv);
        return 0;
    }

    for (int i = 0; option_actions[i].option != NULL; i++) {
        if (strcmp(argv[1], option_actions[i].option) == 0) {
            option_actions[i].action(argc, argv);
            return 0;
        }
    }
    // Si la opción no coincide con ninguna acción conocida, mostrar ayuda
    help_action(argc, argv);
    return 0;
}

