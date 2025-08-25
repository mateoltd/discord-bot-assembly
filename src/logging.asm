; Simple logging helpers for stdout in MASM x64

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

PUBLIC log_cstrln
PUBLIC log_ptr64

STD_OUTPUT_HANDLE EQU -11

.data
crlf    db 13, 10
hex_digits db "0123456789ABCDEF"

.code
; void log_cstrln(char* s)
; RCX = pointer to NUL-terminated string; writes string and CRLF to stdout
log_cstrln PROC
    ; Shadow space (32) + 24 for locals + keep 16-byte alignment
    sub     rsp, 38h

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

    ; Preserve start pointer and length before calling GetStdHandle (which clobbers volatile regs)
    mov     rax, r8                 ; rax = endptr
    sub     rax, r9                 ; rax = start ptr
    mov     [rsp+30h], rax          ; save start ptr (local)
    mov     [rsp+28h], r9           ; save length (local)

    ; GetStdHandle(STD_OUTPUT_HANDLE)
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     r10, rax                ; save handle (volatile is fine across our calls)

    ; WriteFile(h, s, len, NULL, NULL)
    mov     rcx, r10                ; hFile
    mov     rdx, [rsp+30h]          ; lpBuffer = start ptr
    mov     r8,  [rsp+28h]          ; nNumberOfBytesToWrite = len
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
    add     rsp, 38h
    ret
log_cstrln ENDP

; void log_ptr64(void* p)
; RCX = pointer; prints as 0x<16-hex-digits> + CRLF
log_ptr64 PROC
    ; Shadow space (32) + locals (0x28) = 0x58, keep alignment
    sub     rsp, 58h

    ; Save input pointer
    mov     [rsp+40h], rcx

    ; Get handle first (avoid clobbering our buffer later)
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     r10, rax

    ; Build buffer at [rsp+30h]..[rsp+41h] (18 bytes total)
    mov     rax, [rsp+40h]          ; rax = pointer value
    mov     byte ptr [rsp+30h], '0'
    mov     byte ptr [rsp+31h], 'x'
    lea     r11, [rsp+41h]          ; dest = end of 16 hex digits
    mov     r8, rax                 ; r8 = shift source
    lea     rdx, hex_digits
    mov     ecx, 16
lp_hex:
    mov     rax, r8
    and     rax, 0Fh
    mov     al, byte ptr [rdx+rax]
    mov     byte ptr [r11], al
    shr     r8, 4
    dec     r11
    dec     ecx
    jnz     lp_hex

    ; Write pointer string (18 bytes)
    mov     rcx, r10                ; hFile
    lea     rdx, [rsp+30h]          ; buffer start
    mov     r8d, 18                 ; bytes to write
    xor     r9, r9                  ; lpNumberOfBytesWritten = NULL
    mov     qword ptr [rsp+20h], 0  ; lpOverlapped = NULL
    call    WriteFile

    ; Write CRLF
    mov     rcx, r10
    lea     rdx, crlf
    mov     r8d, 2
    xor     r9, r9
    mov     qword ptr [rsp+20h], 0
    call    WriteFile

    xor     eax, eax
    add     rsp, 58h
    ret
log_ptr64 ENDP

END
