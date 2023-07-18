#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <WinUser.h>

using namespace std;

__declspec(naked) void code_cave(DWORD start_pt, DWORD difference_between_iohs, DWORD message) {
    //assembly code to build up the cave
    __asm {
        pop start_pt
        MOV message, EDX
        PUSHAD
        PUSHFD
    }

    //plug the message box here
    cout << message << endl;

    //have the registers restored
    _asm {
        POPFD
        POPAD
        CMP EDX, 0x00001600
        push start_pt
        ret
    }
}

int file_open(FILE* target_file) {
    //initiate flags
    PIMAGE_DOS_HEADER tmp_dos_header;
    int is_pe_file = 0;

    //file reading
    fseek(target_file, 0, SEEK_SET);
    fread(&tmp_dos_header, sizeof(PIMAGE_DOS_HEADER), 1, target_file);

    //flags check
    if (tmp_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        is_pe_file = -1;

    //return flags
    return is_pe_file;
}

PIMAGE_DOS_HEADER retrive_dos_header(FILE* pe_file) {
    //initiate vars
    PIMAGE_DOS_HEADER dos_header;

    //file_reading
    fseek(pe_file, 0, SEEK_SET);
    fread(&dos_header, sizeof(PIMAGE_DOS_HEADER), 1, pe_file);

    //return the header
    return dos_header;
}

PIMAGE_NT_HEADERS retrieve_nt_headers(FILE* pe_file, PIMAGE_DOS_HEADER dos_header) {
    //initiate vars
    PIMAGE_NT_HEADERS nt_headers;

    //file reading
    fseek(pe_file, dos_header->e_lfanew, SEEK_SET);
    fread(&nt_headers, sizeof(PIMAGE_NT_HEADERS), 1, pe_file);

    //return the header
    return nt_headers;
}

DWORD message_box()
{
    int msg = MessageBox(NULL, (LPCWSTR)"You are infected", (LPCWSTR)"Warning", MB_OK);
    return (DWORD)msg;
}

void shell_creation(PIMAGE_NT_HEADERS nt_headers, DWORD message) {
    //get the difference between fileAlignment and sectionAlignment
    DWORD start_pt = (DWORD)(nt_headers->OptionalHeader.FileAlignment);
    DWORD difference_btw_iohs = ((DWORD)nt_headers->OptionalHeader.SectionAlignment - (DWORD)nt_headers->OptionalHeader.FileAlignment);

    //create and utilise the code cave
    code_cave(start_pt, difference_btw_iohs, message);
}

int main(int argc, char* argv[])
{
    //file initiating
    const int MAX_FILEPATH = 255;
    char file_name[MAX_FILEPATH] = { "C:\benign\benign\1aa177b92c99b9458b270907d65d5687af48385fbbf42c3aef9b69d61d284721.exe" }; //sample no26   
    FILE* target_file;
    fopen_s(&target_file, file_name, "rb"); 
    if (target_file == NULL)
        return -1;

    //variables initiating
    DWORD message = NULL;
    PIMAGE_DOS_HEADER dos_header = {};
    PIMAGE_NT_HEADERS image_nt_headers = {};

    //file opening
    bool flag = file_open(target_file);

    // get the necessary headers
    dos_header = retrive_dos_header(target_file);
    image_nt_headers = retrieve_nt_headers(target_file, dos_header);

    //implement the shell creator
    message = message_box();
    shell_creation(image_nt_headers, message);

    return 0;
}

  