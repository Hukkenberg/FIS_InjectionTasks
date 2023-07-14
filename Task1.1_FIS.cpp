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

void print_data_directory(PIMAGE_NT_HEADERS nt_headers) {
    cout << "Export directory address: " << " " << nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress;
    cout << "Export directory size: " << " " << nt_headers->OptionalHeader.DataDirectory[0].Size;
    cout << "Import directory address: " << " " << nt_headers->OptionalHeader.DataDirectory[1].VirtualAddress;
    cout << "Import directory size: " << " " << nt_headers->OptionalHeader.DataDirectory[1].Size;
}

DWORD print_section_headers(PIMAGE_SECTION_HEADER section_header, PIMAGE_SECTION_HEADER import_section, PIMAGE_NT_HEADERS nt_headers) {
    //get section location
    DWORD section_location = (DWORD)nt_headers + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)(nt_headers->FileHeader.SizeOfOptionalHeader);
    DWORD section_size = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    //get offset to import directory RVA
    DWORD import_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    //print section data
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
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

        //export the section location
        if (import_dir_rva >= section_header->VirtualAddress && import_dir_rva < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
            import_section = section_header;
        }
    }
    section_location += section_size;
    return section_location;
}

void print_import_table(PIMAGE_IMPORT_DESCRIPTOR* import_des, DWORD raw_offset, PIMAGE_SECTION_HEADER import_section, DWORD thunk, PIMAGE_THUNK_DATA thunk_data) {
    while (import_dir->Name != 0) {
        cout << raw_offset + (import_des->Name - import_section->VirtualAddress) << endl;
        thunk = import_des->OriginalFirstThunk == 0 ? import_des->FirstThunk : import_des->OriginalFirstThunk;
        thunk_data = (PIMAGE_THUNK_DATA)(raw_offset + (thunk - import_section->VirtualAddress));
        import_dir++;
    }

    while (thunk_data->u1.AddressOfData != 0) {
        if (thunk_data->u1.AddressOfData > 0x80000000) {
            cout << "Ordinal: " << (WORD)thunk_data->u1.AddressOfData;
        } else {
            cout << raw_offset + (thunk_data->u1.AddressOfData - import_section->VirtualAddress + 2) << endl;
        }
        thunk_data++;
    }
}

/*void print_export_table(IMAGE_EXPORT_DIRECTORY* export_dir, DWORD raw_offset, PIMAGE_SECTION_HEADER export_section, DWORD thunk, PIMAGE_THUNK_DATA thunk_data) {
    while (export_dir->Name != 0) {
        cout << raw_offset + (export_des->Name - import_section->VirtualAddress) << endl;
        thunk = export_des->OriginalFirstThunk == 0 ? export_des->FirstThunk : export_des->OriginalFirstThunk;
        thunk_data = (PIMAGE_THUNK_DATA)(raw_offset + (thunk - export_section->VirtualAddress));
        export_dir++;
    }

    while (thunk_data->u1.AddressOfData != 0) {
        if (thunk_data->u1.AddressOfData > 0x80000000) {
            cout << "Ordinal: " << (WORD)thunk_data->u1.AddressOfData;
        }
        else {
            cout << raw_offset + (thunk_data->u1.AddressOfData - import_section->VirtualAddress + 2) << endl;
        }
        thunk_data++;
    }
}*/

int main(int argc, char* argv[])
{
    //file uploading
    const int MAX_FILEPATH = 255;
    char fileName[MAX_FILEPATH] = {"C:/benign/benign/00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe"};
    memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH);
    
    //variables initiating
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;
    PIMAGE_DOS_HEADER dos_header = {};
    PIMAGE_NT_HEADERS image_nt_headers = {};
    PIMAGE_SECTION_HEADER section_header = {};
    PIMAGE_SECTION_HEADER import_section = {};
    PIMAGE_IMPORT_DESCRIPTOR* import_descriptor = NULL;
    IMAGE_EXPORT_DIRECTORY* export_directory = NULL;
    PIMAGE_THUNK_DATA thunk_data = {};
    DWORD thunk = NULL;
    DWORD raw_offset = NULL;


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
    dos_header = (PIMAGE_DOS_HEADER)fileData;
    print_dos_header(dos_header);

    //print NT header
    image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD)fileData + dos_header -> e_lfanew);
    print_nt_headers(image_nt_headers);

    //print PE Header
    print_file_header(image_nt_headers);

    //print optional header
    print_optional_header(image_nt_headers);

    //print data directory
    print_data_directory(image_nt_headers);

    //print section header
    DWORD section_header_location = print_section_headers(section_header, import_section, image_nt_headers);

    //print import table
    raw_offset = (DWORD)fileData + import_section->PointerToRawData;
    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(raw_offset + (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - import_section->VirtualAddress));
    print_import_table(import_descriptor, raw_offset, import_section, thunk, thunk_data);

    //print export table
    //print_export_table(export_directory, raw_offset, export_section, thunk, thunk_data);

    return 0;
}

