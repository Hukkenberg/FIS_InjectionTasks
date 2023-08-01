.386
.model	flat, stdcall
option	casemap :none

include		windows.inc
include		user32.inc
include		kernel32.inc
include		comdlg32.inc
includelib	user32.lib
includelib	kernel32.lib
includelib	comdlg32.lib

DlgProc			PROTO		:DWORD,:DWORD,:DWORD,:DWORD
Validate		PROTO		:DWORD
AddSection		PROTO		:DWORD

.data
;for opening files
MsgBoxCaption   db          "Warning!",0
MsgBoxText      db          "You have been injected!",0
file_name       db          "src_t1.3_fis.txt"
;for creating new sections
strFilter		db			"Executable Files (*.exe, *.dll)",0,
							"*.exe;*.dll",0,"All Files",0,"*.*",0,0 
OpenError		db			"Unable to open target file",0
MsgBoxCap	    db		    "Results",0
Invalid			db			"This is not a valid PE file!!",0
Success			db			"New section added successfully",0
NoSpace			db			"No space for new Section Header",0
Backup			db			".bak",0
;*********VALUES REQUIRED TO CONSTRUCT NEW SECTION************* 
NewSecName		dd			"WEN."
NewSecSize		dd			100h
NewSecChar		dd			0E0000060h
KeepBkup		db			TRUE

.data?
ofn			OPENFILENAME	<>
hInstance	HINSTANCE	?
hTarget		dd		?
hMapping	dd		?
pMapping	dd		?
TargetName	db		512 dup(?)
pPEHeader	dd			?
Buffer		db			512 dup (?)

.const
IDD_MAIN	equ		1001
IDC_TARGET	equ		1003
IDC_OPEN	equ		1004
IDC_BROWSE	equ			1004
IDC_GO 		equ		1005
IDC_EXIT 	equ		1006
ARIcon		equ		2001


.code
start:
	;initiating
	invoke	GetModuleHandle, NULL
	mov	hInstance, eax
	invoke	DialogBoxParam,hInstance,IDD_MAIN,0,addr DlgProc,0
	invoke	ExitProcess, eax
	
	;open the file
	file_opening PROC
		mov eax, 5
		mov ebx, file_name
		mov ecx, 0
		mov edx, 0777
	ret
	flag PROC
		cmp ebx, 0
		jne ecx, 'Success' 
		je ecx, 'File not found'
	ret
	file_reading PROC
		mov eax, 3
   		mov ebx, [fd_in]
   		mov ecx, info
   		mov edx, 26
	ret
	
	;validate the file (if it is a PE file or not)
	DlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
		mov	eax,uMsg
		.if	eax==WM_INITDIALOG
			invoke	LoadIcon,hInstance,2001
			invoke	SendMessage,hWin,WM_SETICON,1,eax
		.elseif eax==WM_COMMAND
			mov	eax,wParam
			.if	eax==IDC_OPEN
				mov ofn.lStructSize,SIZEOF ofn 
				mov ofn.lpstrFilter,offset strFilter
				mov ofn.lpstrFile,offset TargetName 
				mov ofn.nMaxFile,512 
				mov ofn.Flags,OFN_FILEMUSTEXIST+OFN_PATHMUSTEXIST+\
						OFN_LONGNAMES+OFN_EXPLORER+OFN_HIDEREADONLY 
				invoke GetOpenFileName,addr ofn
				.if eax==TRUE
					invoke SetDlgItemText,hWin,IDC_TARGET,addr TargetName
					invoke RtlZeroMemory,addr TargetName,512
				.endif
		.elseif eax==IDC_GO
			invoke GetDlgItemText,hWin,IDC_TARGET,addr TargetName,512
			invoke lstrlen,addr TargetName
			.if eax!=0
				invoke Validate,addr TargetName
			.endif
		.elseif eax==IDC_EXIT
			invoke SendMessage,hWin,WM_CLOSE,0,0
		.endif
		.elseif	eax==WM_CLOSE
			invoke	EndDialog,hWin,0
		.endif
		xor	eax,eax
		ret
	DlgProc endp

	Validate proc FileName:DWORD
		invoke CreateFile,FileName,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0 
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
			.	endif 
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
	Validate EndP

	;create a new section - the guaranteed way to inject the messagebox, code cave is done later
	DlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	mov	eax,uMsg
	.if	eax==WM_INITDIALOG
		invoke	LoadIcon,hInstance,2001
		invoke	SendMessage,hWin,WM_SETICON,1,eax
	.elseif eax==WM_COMMAND
		mov	eax,wParam
		.if	eax==IDC_BROWSE
			mov ofn.lStructSize,SIZEOF ofn 
			mov ofn.lpstrFilter,offset strFilter
			mov ofn.lpstrFile,offset TargetName 
			mov ofn.nMaxFile,512 
			mov ofn.Flags,OFN_FILEMUSTEXIST+OFN_PATHMUSTEXIST+\
						OFN_LONGNAMES+OFN_EXPLORER+OFN_HIDEREADONLY 
			invoke GetOpenFileName,addr ofn
			.if eax==TRUE
				invoke SetDlgItemText,hWin,IDC_TARGET,addr TargetName
				invoke RtlZeroMemory,addr TargetName,512
			.endif
		.elseif eax==IDC_GO
			invoke GetDlgItemText,hWin,IDC_TARGET,addr TargetName,512
			invoke lstrlen,addr TargetName
			.if eax!=0
				invoke Validate,addr TargetName
				.if eax==1
					invoke AddSection,addr TargetName
					.if eax==1
						invoke MessageBox,hWin,addr Success,0,0
					.elseif eax==-1
						invoke MessageBox,hWin,addr NoSpace,0,0
					.endif
				.elseif eax==-1
					invoke MessageBox,hWin,addr Invalid,0,0
				.endif		
			.endif
		.elseif eax==IDC_EXIT
			invoke SendMessage,hWin,WM_CLOSE,0,0
		.endif
	.elseif	eax==WM_CLOSE
		invoke	EndDialog,hWin,0
	.endif
	xor	eax,eax
	ret
	DlgProc endp

	Validate proc FileName:DWORD
	LOCAL ReturnValue:DWORD
	invoke CreateFile,FileName,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0 
	.if eax!=INVALID_HANDLE_VALUE
		mov hTarget,eax
		invoke CreateFileMapping,eax,0,PAGE_READONLY,0,0,0 
		mov hMapping,eax
		invoke MapViewOfFile,eax,FILE_MAP_READ,0,0,0 
		mov pMapping,eax 
		.if [eax.IMAGE_DOS_HEADER.e_magic]==IMAGE_DOS_SIGNATURE
			add eax,[eax.IMAGE_DOS_HEADER.e_lfanew]
			.if [eax.IMAGE_NT_HEADERS.Signature]==IMAGE_NT_SIGNATURE
				mov ReturnValue,1
				jmp @EXIT
			.endif 
		.else 
			mov ReturnValue,-1
			jmp @EXIT
		.endif 
	@EXIT:
		invoke UnmapViewOfFile,pMapping
		invoke CloseHandle,hMapping
		invoke CloseHandle,hTarget
		mov eax,ReturnValue
		ret
	.else
		invoke MessageBox,0,addr OpenError,0,0
		xor eax,eax
		Ret
	.endif
	Validate EndP

	AddSection proc FileName:DWORD 
	LOCAL ReturnValue:DWORD
	;*******MAKE BACKUP***************************************************
	invoke lstrcpy,addr Buffer,FileName
	invoke lstrcat,addr Buffer,addr Backup		
	invoke CopyFile,FileName,addr Buffer,TRUE
	;*******OPEN FILE MAP IN AND INCREASE SIZE****************************
	invoke CreateFile,FileName,GENERIC_READ+GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0 
	.if eax!=INVALID_HANDLE_VALUE
		mov hTarget,eax
		invoke GetFileSize,eax,0
		add eax,NewSecSize
		invoke CreateFileMapping,hTarget,0,PAGE_READWRITE,0,eax,0 
		mov hMapping,eax
		invoke MapViewOfFile,eax,FILE_MAP_ALL_ACCESS,0,0,0 
		mov pMapping,eax 
	;******CHECK ENOUGH ROOM FOR NEW ISH IN SECTION TABLE******************
		add eax,[eax.IMAGE_DOS_HEADER.e_lfanew]	;pointer to PE header in eax
		mov pPEHeader,eax
		movzx esi,[eax.IMAGE_NT_HEADERS.FileHeader.NumberOfSections];no of sections in ecx
		inc esi									;add 1
		imul esi,esi,40							;calc size of all ISHs
		add esi,0F8h							;add above to offset of sec table from PE header
		mov ebx,pMapping
		add esi,[ebx.IMAGE_DOS_HEADER.e_lfanew]	;add above to offset of PE header from beginning of file
		.if esi<[eax.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders]	;cmp offset of end of new ISH to offset of first section
	;*******IF SO FILL NEW ISH**********************************************
			add esi,ebx							;make above offset into a pointer by adding base address
			sub esi,40							
			mov edi,esi							;pointer to start of new ISH in edi
			sub esi,40							;pointer to start of last ISH in esi
			mov eax,NewSecName
			mov dword ptr [edi.IMAGE_SECTION_HEADER.Name1],eax	;write in Name1
			mov eax,NewSecSize
			mov [edi.IMAGE_SECTION_HEADER.Misc.VirtualSize],eax	;write in virtual size
			xor edx,edx											;align raw size of new sec
			mov ebx,pPEHeader									
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment]
			div ecx				;divides file alignment by raw size, quotient into eax, remainder into edx
			.if edx!=0			;if no remainder, ie already aligned then multiply back up								
				inc eax			;if there is remainder, ie not aligned, then
			.endif				;add 1 to quotient and multiply back up (rounds up to alignment value)
			mul ecx
			mov [edi.IMAGE_SECTION_HEADER.SizeOfRawData],eax	;write in raw size
			mov eax,[esi.IMAGE_SECTION_HEADER.VirtualAddress]	;get RVA of last section
			add eax,[esi.IMAGE_SECTION_HEADER.Misc.VirtualSize]	;add virt size of last sec to get RVA of new sec
			xor edx,edx											;align RVA of new sec
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment]
			div ecx
			.if edx!=0
				inc eax
			.endif
			mul ecx
			mov [edi.IMAGE_SECTION_HEADER.VirtualAddress],eax	;write in RVA of new sec
			mov eax,[esi.IMAGE_SECTION_HEADER.PointerToRawData]	;get raw offset of last sec
			add eax,[esi.IMAGE_SECTION_HEADER.SizeOfRawData]	;add raw size
			xor edx,edx											;align raw offset
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.FileAlignment]
			div ecx
			.if edx!=0
				inc eax
			.endif
			mul ecx
			mov [edi.IMAGE_SECTION_HEADER.PointerToRawData],eax	;write in raw offset of new sec
			mov edx,NewSecChar
			mov [edi.IMAGE_SECTION_HEADER.Characteristics],edx	;write in new sec characteristics
			.if edx!=0
				inc eax
			.endif
			mul ecx
			message equ invoke MessageBox, NULL, addr MsgBoxText, addr MsgBoxCaption, MB_OK
			mov [edi.IMAGE_SECTION_HEADER.Characteristics + 0x00001000], message    ;call the MsgBox
	;*******UPDATE PE HEADER***********************************************
			mov eax,[edi.IMAGE_SECTION_HEADER.Misc.VirtualSize]	;get new sec virt size
			xor edx,edx											;align to section alignment
			mov ecx,[ebx.IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment]
			div ecx
			.if edx!=0
				inc eax
			.endif
			mul ecx
			add eax,[edi.IMAGE_SECTION_HEADER.VirtualAddress]	;add RVA where new section begins in memory
			mov [ebx.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage],eax	;write new size of image
			inc [ebx.IMAGE_NT_HEADERS.FileHeader.NumberOfSections];add 1 to no of sections
			mov ReturnValue,1
			jmp @EXIT
		.else
	;*******IF NO SPACE THEN RESTORE FROM BACKUP AND DELETE BACKUP**********
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
	;*******DECIDE WHETHER TO KEEP BACKUP AFTER SUCCESS*********************
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
	AddSection EndP
end start  

;credentials: ARTEam Win32 Assembly for Crackers, Goppit