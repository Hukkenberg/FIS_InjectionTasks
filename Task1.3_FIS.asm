.386 
.model flat, stdcall 
.stack 4096
assume fs:nothing

include windows.inc
include kernel32.inc  
include user32.inc
includelib kernel32.lib  
includelib user32.lib
	
.code 	
	main proc		
		; form new stack frame		
		push ebp		
		mov ebp, esp
		; allocate local variables and initialize them to 0		
		sub esp, 1ch		
		xor eax, eax		
		mov [ebp - 04h], eax
		mov [ebp - 08h], eax			
		mov [ebp - 0ch], eax
		mov [ebp - 10h], eax
		mov [ebp - 14h], eax			
		mov [ebp - 18h], eax		
		mov [ebp - 1ch], eax
		; push WinExec to stack and save it to a local variable
		push 00636578h
		push 456e6957h
		mov [ebp - 14h], esp
		; get kernel32 base address
		mov eax, [fs:30h]
		mov eax, [eax + 0ch]
		mov eax, [eax + 14h]
		mov eax, [eax]
		mov eax, [eax] 
		mov eax, [eax -8h + 18h]
		; kernel32 base address
		mov ebx, eax
		; get address of PE signature
		mov eax, [ebx + 3ch]
		add eax, ebx
		; get address of Export Table		
		mov eax, [eax + 78h]			
		add eax, ebx
		; get number of exported functions		
		mov ecx, [eax + 14h]				
		mov [ebp - 4h], ecx
		; get address of exported functions table		
		mov ecx, [eax + 1ch]			
		add ecx, ebx	
		mov [ebp - 8h], ecx	
		; get address of name pointer table		
		mov ecx, [eax + 20h]			
		add ecx, ebx					    
		mov [ebp - 0ch], ecx
		; get address of functions ordinal table		
		mov ecx, [eax + 24h]					
		add ecx, ebx					    		
		mov [ebp - 10h], ecx				
		; loop through exported function name pointer table and find position of WinExec		
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
			jmp eax
			ret
		; exit		
		add esp, 1ch											
		add esp, 0ch									
		add esp, 4h									
		pop ebp		
	main endp	
end main
