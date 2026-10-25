OPTION CASEMAP:NONE

.code

InvocationAlignment PROC
    mov rax, rsp
    and rax, 15
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9
    ret
InvocationAlignment ENDP

InvocationClobberFault PROC
    mov rbx, 1
    mov rbp, 2
    mov rsi, 3
    mov rdi, 4
    mov r12, 5
    mov r13, 6
    mov r14, 7
    mov r15, 8
    pcmpeqb xmm6, xmm6
    pcmpeqb xmm7, xmm7
    pcmpeqb xmm8, xmm8
    pcmpeqb xmm9, xmm9
    pcmpeqb xmm10, xmm10
    pcmpeqb xmm11, xmm11
    pcmpeqb xmm12, xmm12
    pcmpeqb xmm13, xmm13
    pcmpeqb xmm14, xmm14
    pcmpeqb xmm15, xmm15
    ud2
    ret
InvocationClobberFault ENDP

END
