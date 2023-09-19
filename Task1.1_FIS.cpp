#include <iostream>
#include "Windows.h"

using namespace std;

void print_dos_header(PIMAGE_DOS_HEADER dos_header) {
    //print the dos header.
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
    //print the file signature.
    cout << "NT HEADERS" << endl;
    cout << "Signature: " << " " << image_nt_headers->Signature << endl;
}

void print_file_header(PIMAGE_NT_HEADERS nt_headers) {
    //print the PE header.
    cout << "Machine: " << " " << nt_headers->FileHeader.Machine << endl;
    cout << "Number of sections: " << " " << nt_headers->FileHeader.NumberOfSections << endl;
    cout << "Time stamp: " << " " << nt_headers->FileHeader.TimeDateStamp << endl;
    cout << "Pointer to symbol table: " << " " << nt_headers->FileHeader.PointerToSymbolTable << endl;
    cout << "Number of symbols: " << " " << nt_headers->FileHeader.NumberOfSymbols << endl;
    cout << "Size of optional header: " << " " << nt_headers->FileHeader.SizeOfOptionalHeader;
    cout << "Characteristic: " << " " << nt_headers->FileHeader.Characteristics << endl;
}

void print_optional_header(PIMAGE_NT_HEADERS nt_headers) {
    //print the optional header.
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

void print_data_directory(PIMAGE_NT_HEADERS nt_headers) {
    cout << "Export directory address: " << " " << nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress;
    cout << "Export directory size: " << " " << nt_headers->OptionalHeader.DataDirectory[0].Size;
    cout << "Import directory address: " << " " << nt_headers->OptionalHeader.DataDirectory[1].VirtualAddress;
    cout << "Import directory size: " << " " << nt_headers->OptionalHeader.DataDirectory[1].Size;
}

void print_section_headers(PIMAGE_SECTION_HEADER section_header, PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER import_section) {
    cout << "SECTION HEADER" << endl;

    //find the starting location and size of the sections.
    DWORD section_location = (DWORD)nt_headers + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)nt_headers->FileHeader.SizeOfOptionalHeader;
    DWORD section_size = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    //initiate the rva address of import and export sections
    DWORD import_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    //the printing loop
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        //print the raw information of section headers
        section_header = (PIMAGE_SECTION_HEADER)section_location;
        cout << "Name: " << " " << section_header->Name << endl;
        cout << "Virtual size: " << " " << section_header->Misc.VirtualSize << endl;
        cout << "Virtual address: " << " " << section_header->VirtualAddress << endl;
        cout << "Size of raw data: " << " " << section_header->SizeOfRawData << endl;
        cout << "Pointer to raw data: " << " " << section_header->PointerToRawData << endl;
        cout << "Pointer to relocations: " << " " << section_header->PointerToRelocations << endl;
        cout << "Pointer to line numbers: " << " " << section_header->PointerToLinenumbers << endl;
        cout << "Number of relocations: " << " " << section_header->NumberOfRelocations << endl;
        cout << "Number of line numbers: " << section_header->NumberOfLinenumbers << endl;
        cout << "Characteristics: " << section_header->Characteristics << endl;

        //extract the import section
        if (import_dir_rva >= section_header->VirtualAddress && import_dir_rva < section_header->VirtualAddress + section_header->Misc.VirtualSize) {
            import_section = section_header;
        }

        //continue the loop
        section_location += section_size;
    }
}

void print_import_export_table(PIMAGE_SECTION_HEADER import_section, PIMAGE_NT_HEADERS nt_headers, DWORD raw_offset, DWORD thunk) {
    //parse DLL imports
    cout << "DLL IMPORTS/EXPORTS" << endl;
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(raw_offset + (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - import_section->VirtualAddress));
    while (import_descriptor->Name != 0) {
        cout << raw_offset + (import_descriptor->Name - import_section->VirtualAddress) << endl;
        if (import_descriptor->OriginalFirstThunk == 0) {
            thunk = import_descriptor->FirstThunk; 
        } else {
            thunk = import_descriptor->OriginalFirstThunk;
        }
        PIMAGE_THUNK_DATA thunk_data = (PIMAGE_THUNK_DATA)(raw_offset + (thunk - import_section->VirtualAddress));

        //parse relevant DLL exports
        while (thunk_data->u1.AddressOfData != 0) {
            if (thunk_data->u1.AddressOfData > 0x80000000) {
                cout << "Ordinal: " << " " << (WORD)thunk_data->u1.AddressOfData;
            } else {
                cout << raw_offset + (thunk_data->u1.AddressOfData - import_section->VirtualAddress + 2);
            }
            thunk_data++;
        }
        import_descriptor++;
    }
}

int main(int argc, char* argv[])
{
    //file uploading
    const int MAX_FILEPATH = 255;
    char file_name[MAX_FILEPATH] = { "C:/benign/benign/00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe" };
    if (argv[1] == NULL)
        return -20;
    memcpy_s(&file_name, MAX_FILEPATH, argv[1], MAX_FILEPATH);
    if (&file_name == NULL)
        return -10;

    //variables initiating
    HANDLE file = NULL;
    DWORD file_size = NULL;
    DWORD bytes_read = NULL;
    DWORD thunk = NULL;
    LPVOID file_data = NULL;
    PIMAGE_DOS_HEADER dos_header = {};
    PIMAGE_NT_HEADERS image_nt_headers = {};
    PIMAGE_SECTION_HEADER section_header = {};
    PIMAGE_SECTION_HEADER import_section = {};

    //file open
    file = CreateFileA(file_name, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        cout << "Couldn't read file!";
        return 1;
    }

    //heap allocation
    file_size = GetFileSize(file, NULL);
    if (file_size == NULL)
        return -2;
    file_data = HeapAlloc(GetProcessHeap(), 0, file_size);
    if (file_data == NULL)
        return -3;

    //read file bytes to memory
    bool flag = ReadFile(file, file_data, file_size, &bytes_read, NULL);
    if (flag == false) return -1;
  
    //print DOS Header
    dos_header = (PIMAGE_DOS_HEADER)file_data;
    if (dos_header == NULL) {
        return -11;
    }
    print_dos_header(dos_header);

    //print NT header
    image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD)file_data + dos_header -> e_lfanew);
    print_nt_headers(image_nt_headers);

    //print PE Header
    print_file_header(image_nt_headers);

    //print optional header
    print_optional_header(image_nt_headers);

    //print data directory
    print_data_directory(image_nt_headers);

    //print section header
    print_section_headers(section_header, image_nt_headers, import_section);

    //print import table
    if (import_section == NULL || file_data == NULL) {
        return -111;
    }
    DWORD raw_offset = (DWORD)file_data + import_section->PointerToRawData;

    print_import_export_table(import_section, image_nt_headers, raw_offset, thunk);

    //print export table

    return 0;
}

