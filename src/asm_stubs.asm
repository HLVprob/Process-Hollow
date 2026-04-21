EXTERN g_syscall_ssn : DWORD

.CODE

ghost_get_peb PROC
    mov rax, gs:[60h]   ; TEB -> ProcessEnvironmentBlock
    ret
ghost_get_peb ENDP

ghost_do_syscall PROC
    mov r10, rcx                        ; kernel wants: R10 = 1st arg
    mov eax, DWORD PTR [g_syscall_ssn]  ; SSN into EAX
    syscall
    ret
ghost_do_syscall ENDP

END