#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <WinUser.h>

using namespace std;

DWORD message_box()
{
    int msg = MessageBox(NULL, (LPCWSTR)"You are infected", (LPCWSTR)"Warning", MB_OK);
    return (DWORD)msg;
}

void shell_creation(PIMAGE_NT_HEADERS nt_headers) { 
    //retrieve the optional header
    cout << nt_headers->OptionalHeader.FileAlignment << endl;
    cout << nt_headers->OptionalHeader.SectionAlignment << endl;

    //get the difference between fileAlignment and sectionAlignment
    DWORD start_pt = (DWORD)(nt_headers->OptionalHeader.FileAlignment);
    DWORD difference_btw_iohs = ((DWORD)nt_headers->OptionalHeader.SectionAlignment - (DWORD)nt_headers->OptionalHeader.FileAlignment);

    //allocate the msgbox
    DWORD_PTR start_pos[2] = { (DWORD_PTR)start_pt, NULL };
    DWORD content = message_box();
    if (content <= difference_btw_iohs) {
        start_pos[1] = content;
    }
    cout << start_pos;
}

int main()
{
    //get the image base
    PVOID image_base = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
    PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_base + dos_header->e_lfanew);

    //implement the shell creator
    shell_creation(image_nt_headers);

    return 0;
}
