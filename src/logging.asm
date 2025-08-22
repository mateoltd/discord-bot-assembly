; Simple logging helpers for stdout in MASM x64

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

PUBLIC log_cstrln

STD_OUTPUT_HANDLE EQU -11

.data
crlf    db 13, 10

.code
; void log_cstrln(char* s)
; RCX = pointer to NUL-terminated string; writes string and CRLF to stdout
log_cstrln PROC
    ; Shadow space (32) + 8 for alignment like in main
    sub     rsp, 28h

    ; Compute length of C-string: r8 = ptr, r9d = len
    mov     r8, rcx
    xor     r9d, r9d
len_loop:
    cmp     byte ptr [r8], 0
    je      len_done
    inc     r8
    inc     r9d
    jmp     len_loop
len_done:

    ; GetStdHandle(STD_OUTPUT_HANDLE)
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     r10, rax                ; save handle (volatile is fine across our calls)

    ; WriteFile(h, s, len, NULL, NULL)
    mov     rcx, r10                ; hFile
    mov     rdx, r8                 ; rdx = endptr
    mov     rax, r9                 ; rax = len (zero-extended)
    sub     rdx, rax                ; rdx = start ptr
    mov     r8d, r9d                ; nNumberOfBytesToWrite
    xor     r9, r9                  ; lpNumberOfBytesWritten = NULL
    mov     qword ptr [rsp+20h], 0  ; lpOverlapped = NULL
    call    WriteFile

    ; Write CRLF
    mov     rcx, r10                ; hFile
    lea     rdx, crlf
    mov     r8d, 2
    xor     r9, r9
    mov     qword ptr [rsp+20h], 0
    call    WriteFile

    xor     eax, eax
    add     rsp, 28h
    ret
log_cstrln ENDP

END
