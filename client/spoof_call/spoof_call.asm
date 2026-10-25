OPTION CASEMAP:NONE

.code

RrmSpoofStub PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 088h
    .allocstack 088h
    .endprolog

    mov rax, [rsp + 088h]
    mov [rcx + 0B0h], rax
    mov [rcx + 0B8h], rbp
    mov [rcx + 0C0h], rsi
    mov [rcx + 0C8h], rdi
    mov [rcx + 0D0h], r12
    mov [rcx + 0D8h], r13
    mov [rcx + 0E0h], r14
    mov [rcx + 0E8h], r15
    movdqu [rcx + 0F0h], xmm6
    movdqu [rcx + 100h], xmm7
    movdqu [rcx + 110h], xmm8
    movdqu [rcx + 120h], xmm9
    movdqu [rcx + 130h], xmm10
    movdqu [rcx + 140h], xmm11
    movdqu [rcx + 150h], xmm12
    movdqu [rcx + 160h], xmm13
    movdqu [rcx + 170h], xmm14
    movdqu [rcx + 180h], xmm15
    stmxcsr [rcx + 190h]
    fnstcw [rcx + 194h]
    mov rbx, rcx

    mov r10, 4
copy_arguments:
    mov rax, [rbx + r10 * 8 + 8]
    mov [rsp + r10 * 8 + 8], rax
    inc r10
    cmp r10, 16
    jb copy_arguments

    mov rax, [rbx]
    mov [rsp], rax
    lea rax, [rsp + 8]
    mov [rbx + 088h], rax
    lea rax, resume_call
    mov [rbx + 090h], rax
    mov DWORD PTR [rbx + 198h], 1

    movq xmm0, QWORD PTR [rbx + 8]
    movq xmm1, QWORD PTR [rbx + 16]
    movq xmm2, QWORD PTR [rbx + 24]
    movq xmm3, QWORD PTR [rbx + 32]
    mov rcx, [rbx + 8]
    mov rdx, [rbx + 16]
    mov r8, [rbx + 24]
    mov r9, [rbx + 32]
    mov r11, [rbx]
    jmp r11

resume_call:
    mov [rbx + 098h], rax
    movdqu [rbx + 0A0h], xmm0
    movdqu xmm6, [rbx + 0F0h]
    movdqu xmm7, [rbx + 100h]
    movdqu xmm8, [rbx + 110h]
    movdqu xmm9, [rbx + 120h]
    movdqu xmm10, [rbx + 130h]
    movdqu xmm11, [rbx + 140h]
    movdqu xmm12, [rbx + 150h]
    movdqu xmm13, [rbx + 160h]
    movdqu xmm14, [rbx + 170h]
    movdqu xmm15, [rbx + 180h]
    ldmxcsr [rbx + 190h]
    fldcw [rbx + 194h]
    mov rbp, [rbx + 0B8h]
    mov rsi, [rbx + 0C0h]
    mov rdi, [rbx + 0C8h]
    mov r12, [rbx + 0D0h]
    mov r13, [rbx + 0D8h]
    mov r14, [rbx + 0E0h]
    mov r15, [rbx + 0E8h]
    cld
    add rsp, 080h
    pop rbx
    ret
RrmSpoofStub ENDP

END
