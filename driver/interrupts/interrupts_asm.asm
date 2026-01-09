PUBLIC nmi_isr
EXTERN nmi_handler:PROC

save_gprs MACRO
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
ENDM

restore_gprs MACRO
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
ENDM

nmi_isr PROC
    save_gprs

    sub rsp, 40h
    call nmi_handler ; emulate KiNmiInterrupt or use windows default nmi handler
    add rsp, 40h

    restore_gprs
    iretq
nmi_isr ENDP
