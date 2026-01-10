OPTION CASEMAP:NONE

PUBLIC nmi_isr
EXTERN nmi_handler:PROC
EXTERN g_nmi_shellcode:qword

PUBLIC read_cs
PUBLIC swap_gs
_TEXT SEGMENT

nmi_isr PROC
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    sub rsp, 40h
    call nmi_handler
    add rsp, 40h

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    jmp qword ptr [g_nmi_shellcode]
    ; iretq
nmi_isr ENDP

read_cs PROC ; i dont have __readcs() in my intrin.h for some reason i guess..
    mov ax, cs
    ret
read_cs ENDP

swap_gs PROC
    swapgs
    ret
swap_gs ENDP

_TEXT ENDS
END
