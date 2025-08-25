; Core string helpers (C-strings) for MASM x64

OPTION PROLOGUE:none
OPTION EPILOGUE:none

PUBLIC str_len
PUBLIC str_cmp
PUBLIC str_ncmp
PUBLIC str_eq
EXTERN log_cstrln:PROC

.code
; size_t str_len(const char* s)
; RCX = s, returns RAX = length (not including NUL)
str_len PROC
    sub     rsp, 28h
    ; Save input pointer for logging and restore after
    mov     [rsp+20h], rcx
    lea     rcx, sl_msg_enter
    call    log_cstrln
    mov     rcx, [rsp+20h]
    test    rcx, rcx
    jz      sl_null
    mov     rax, rcx        ; rax = cur
sl_loop:
    cmp     byte ptr [rax], 0
    je      sl_done
    inc     rax
    jmp     sl_loop
sl_done:
    sub     rax, rcx        ; rax = cur - start
    mov     [rsp+18h], rax  ; preserve length across log call
    lea     rcx, sl_msg_done
    call    log_cstrln
    mov     rax, [rsp+18h]  ; restore computed length as return value
    add     rsp, 28h
    ret
sl_null:
    xor     rax, rax        ; return 0 for NULL string
    add     rsp, 28h
    ret
str_len ENDP

; int str_cmp(const char* a, const char* b)
; RCX=a, RDX=b, returns EAX <0, 0, >0 like strcmp
str_cmp PROC
    sub     rsp, 28h
sc_loop:
    mov     al, byte ptr [rcx]
    mov     r8b, byte ptr [rdx]
    cmp     al, r8b
    jne     sc_diff
    test    al, al
    je      sc_equal
    inc     rcx
    inc     rdx
    jmp     sc_loop
sc_diff:
    ; return (int)al - (int)r8b (sign-extended to 32-bit)
    movzx   eax, al
    movzx   r9d, r8b
    sub     eax, r9d
    add     rsp, 28h
    ret
sc_equal:
    xor     eax, eax
    add     rsp, 28h
    ret
str_cmp ENDP

; int str_ncmp(const char* a, const char* b, size_t n)
; RCX=a, RDX=b, R8=n, returns like strncmp
str_ncmp PROC
    sub     rsp, 28h
    test    r8, r8
    jz      sn_equal
sn_loop:
    mov     al, byte ptr [rcx]
    mov     r9b, byte ptr [rdx]
    cmp     al, r9b
    jne     sn_diff
    test    al, al
    je      sn_equal
    dec     r8
    jz      sn_equal
    inc     rcx
    inc     rdx
    jmp     sn_loop
sn_diff:
    movzx   eax, al
    movzx   r10d, r9b
    sub     eax, r10d
    add     rsp, 28h
    ret
sn_equal:
    xor     eax, eax
    add     rsp, 28h
    ret
str_ncmp ENDP

; int str_eq(const char* a, const char* b)
; RCX=a, RDX=b, returns EAX = 1 if equal, 0 otherwise
str_eq PROC
    sub     rsp, 28h
    call    str_cmp
    test    eax, eax
    jne     se_no
    mov     eax, 1
    add     rsp, 28h
    ret
se_no:
    xor     eax, eax
    add     rsp, 28h
    ret
str_eq ENDP

; debug strings
.data
sl_msg_enter db "sl: enter",0
sl_msg_done  db "sl: done",0

.code
END
