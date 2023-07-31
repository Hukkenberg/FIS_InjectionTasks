.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib

.data
MsgBoxCaption  db "Warning!",0
MsgBoxText     db "You have been injected!",0
file_name      db 'src_t1.3_fis.txt'

.code
start:
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
	get_kernel32 PROC
		xor ecx, ecx                
		mul ecx                    
		mov eax, [fs:ecx + 0x030]   
		mov eax, [eax + 0x00c]      
		mov esi, [eax + 0x014]      
		lodsd                       
		xchg esi, eax				
		lodsd                       
		mov ebx, [eax + 0x10] 
		ret  
	get_address_of_name PROC
		mov edx, [ebx + 0x3c]       
		add edx, ebx				
		mov edx, [edx + 0x78]       
		add edx, ebx
		mov esi, [edx + 0x20]       
		add esi, ebx
		xor ecx, ecx 
	ret  
	get_proc_address PROC
		inc ecx                             
		lodsd                               
		add eax, ebx				
		cmp dword [eax], 0x50746547         
		jnz get_proc_address
		cmp dword [eax + 0x4], 0x41636F72   
		jnz get_proc_address
		cmp dword [eax + 0x8], 0x65726464   
		jnz get_proc_address
	ret 
	get_proc_address_func PROC
		mov esi, [edx + 0x24]       
		add esi, ebx                
		mov cx, [esi + ecx * 2]     
		dec ecx
		mov esi, [edx + 0x1c]       
		add esi, ebx                
		mov edx, [esi + ecx * 4]   
		add edx, ebx                
		mov ebp, edx                
	ret
	get_load_library_a PROC
		xor ecx, ecx                
		push ecx                    
		push 0x41797261             
		push 0x7262694c             
		push 0x64616f4c             
		push esp
		push ebx                    
		call edx                    
	ret
	get_user_32 PROC
		push 0x61616c6c                
		sub word [esp + 0x2], 0x6161    
		push 0x642e3233                  
		push 0x72657355                  
		push esp
		call eax  
	ret
	get_message_box PROC
		push 0x6141786f                 
		sub [esp + 0x3], 0x61
		push 0x42656761                 
		push 0x7373654d	                
		push esp
		push eax                        
		call ebp                        
	ret                      
	invoke MessageBox, NULL, addr MsgBoxText, addr MsgBoxCaption, MB_OK
	invoke ExitProcess, NULL
end start  

;credentials: https://blackcloud.me/Win32-shellcode-3/, https://left404.com/2011/01/04/converting-x86-assembly-from-masm-to-nasm-3/ (for translation to MASM and tuneups)