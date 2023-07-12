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

int main(int argc, char* argv[])
{
    //get the PE file
    const int MAX_FILEPATH = 255;
    char fileName[MAX_FILEPATH] = { "C:/benign/benign/00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe" };
    memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH); //exception handling needed

    //parameters initiation
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

    // get the necessary headers
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dos_header->e_lfanew);

    //implement the shell creator
    shell_creation(image_nt_headers);

    return 0;
}
