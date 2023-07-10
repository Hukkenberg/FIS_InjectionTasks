#include <iostream>
#include "Windows.h"

using namespace std;

void print_dos_header(PIMAGE_DOS_HEADER dos_header) {
    cout << "DOS HEADER" << endl;
    cout << "PE Magic number: " << " " << dos_header -> e_magic << endl;
    cout << "Bytes on the last page of file: " << dos_header -> e_cblp << endl;
    cout << "Pages in file: " << " " << dos_header -> e_cp << endl;
    cout << "Relocations: " << " " << dos_header -> e_crlc << endl;
    cout << "Size of header in paragraphs: " << " " << dos_header -> e_cparhdr << endl;
    cout << "Minimum extra paragraphs needed: " << " " << dos_header -> e_minalloc << endl;
    cout << "Maximum extra paragraphs needed: " << " " << dos_header -> e_maxalloc << endl;
    cout << "Initial (relative) SS value: " << " " << dos_header -> e_ss << endl;
    cout << "Initial SP value: " << " " << dos_header -> e_sp << endl;
    cout << "Checksum: " << " " << dos_header -> e_csum << endl;
    cout << "Initial IP value: " << " " << dos_header -> e_ip << endl;
    cout << "Initial (relative) CS value: " << " " << dos_header -> e_cs << endl;
    cout << "File address of relocation table: " << " " << dos_header -> e_lfarlc << endl;
    cout << "Overlay number: " << " " << dos_header -> e_ovno << endl;
    cout << "Reserved words: " << " " << dos_header -> e_res << endl;
    cout << "OEM identifier (for e_oeminfo): " << " " << dos_header -> e_oemid << endl;
    cout << "OEM information: " << " " << dos_header -> e_oeminfo << endl;
    cout << "Reserved words: " << " " << dos_header -> e_res2 << endl;
    cout << "File address of new exe header: " << " " << dos_header -> e_lfanew << endl;
}

void print_nt_headers(PIMAGE_NT_HEADERS image_nt_headers) {
    cout << "NT HEADERS" << endl;
    cout << "Signature: " << " " << image_nt_headers->Signature << endl;
}

void print_file_header(PIMAGE_NT_HEADERS nt_headers) {
    cout << "Machine: " << " " << nt_headers->FileHeader.Machine << endl;
    cout << "Number of sections: " << " " << nt_headers->FileHeader.NumberOfSections << endl;
    cout << "Time stamp: " << " " << nt_headers->FileHeader.TimeDateStamp << endl;
    cout << "Pointer to symbol table: " << " " << nt_headers->FileHeader.PointerToSymbolTable << endl;
    cout << "Number of symbols: " << " " << nt_headers->FileHeader.NumberOfSymbols << endl;
    cout << "Size of optional header: " << " " << nt_headers->FileHeader.SizeOfOptionalHeader;
    cout << "Characteristic: " << " " << nt_headers->FileHeader.Characteristics << endl;
}

void print_optional_header(PIMAGE_NT_HEADERS nt_headers) {
    cout << "Magic number: " << " " << nt_headers -> OptionalHeader.Magic << endl;
    cout << "Major linker version: " << " " << nt_headers -> OptionalHeader.MajorLinkerVersion << endl;
    cout << "Minor linker version: " << " " << nt_headers -> OptionalHeader.MinorLinkerVersion << endl;
    cout << "Size of code: " << " " << nt_headers -> OptionalHeader.SizeOfCode << endl;
    cout << "Size of initalized data: " << " " << nt_headers -> OptionalHeader.SizeOfInitializedData << endl;
    cout << "Size of uninitalized data: " << " " << nt_headers -> OptionalHeader.SizeOfUninitializedData << endl;
    cout << "Address of entry point: " << " " << nt_headers -> OptionalHeader.AddressOfEntryPoint << endl;
    cout << "Base of code: " << " " << nt_headers -> OptionalHeader.BaseOfCode << endl;
    cout << "Image base: " << " " << nt_headers -> OptionalHeader.ImageBase << endl;
    cout << "Section alignment: " << " " << nt_headers -> OptionalHeader.SectionAlignment << endl;
    cout << "File alignment: " << " " << nt_headers -> OptionalHeader.FileAlignment << endl;
    cout << "Major operating system version: " << " " << nt_headers -> OptionalHeader.MajorOperatingSystemVersion << endl;
    cout << "Minor operating system version: " << " " << nt_headers -> OptionalHeader.MinorOperatingSystemVersion << endl;
    cout << "Major image version: " << " " << nt_headers -> OptionalHeader.MajorImageVersion << endl;
    cout << "Minor image version: " << " " << nt_headers -> OptionalHeader.MinorImageVersion << endl;
    cout << "Major subsystem version: " << " " << nt_headers -> OptionalHeader.MajorSubsystemVersion << endl;
    cout << "Minor subsystem version: " << " " << nt_headers -> OptionalHeader.MinorSubsystemVersion << endl;
    cout << "Size of image: " << " " << nt_headers -> OptionalHeader.SizeOfImage << endl;
    cout << "Size of headers: " << " " << nt_headers -> OptionalHeader.SizeOfHeaders << endl;
    cout << "Checksum: " << " " << nt_headers -> OptionalHeader.CheckSum << endl;
    cout << "Subsystem: " << " " << nt_headers -> OptionalHeader.Subsystem << endl;
    cout << "Dll characteristics: " << " " << nt_headers -> OptionalHeader.DllCharacteristics << endl;
    cout << "Size of stack reserve: " << " " << nt_headers -> OptionalHeader.SizeOfStackReserve << endl;
    cout << "Size of stack commit: " << " " << nt_headers -> OptionalHeader.SizeOfStackCommit << endl;
    cout << "Size of heap reserve: " << " " << nt_headers -> OptionalHeader.SizeOfHeapReserve << endl;
    cout << "Size of heap commit: " << " " << nt_headers -> OptionalHeader.SizeOfHeapCommit << endl;
    cout << "Loader flag: " << " " << nt_headers -> OptionalHeader.LoaderFlags << endl;
    cout << "Number of data directories: " << " " << nt_headers -> OptionalHeader.NumberOfRvaAndSizes << endl;
}

int main(int argc, char* argv[])
{
    //variables uploading
    const int MAX_FILEPATH = 255;
    char fileName[MAX_FILEPATH] = {"C:/benign/benign/00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe"};
    memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH);
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;
    PIMAGE_DOS_HEADER dosHeader = {};
    PIMAGE_NT_HEADERS imageNTHeaders = {};

    //file open
    file = CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        cout << "Couldn't read file!";
        return 1;
    }

    //heap allocation
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

    // read file bytes to memory
    bool flag = ReadFile(file, fileData, fileSize, &bytesRead, NULL);
    if (flag == false) return -1;
  
    //print DOS Header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)fileData;
    print_dos_header(dos_header);

    //print NT header
    PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD)fileData + dos_header -> e_lfanew);
    print_nt_headers(image_nt_headers);

    //print PE Header
    print_file_header(image_nt_headers);

    //print optional header
    print_optional_header(image_nt_headers);

    return 0;
}

