; Base64 helpers using CryptBinaryToStringA

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN CryptBinaryToStringA:PROC
EXTERN GetLastError:PROC
EXTERN heap_alloc:PROC
EXTERN heap_free:PROC
EXTERN log_cstrln:PROC
EXTERN log_ptr64:PROC

PUBLIC base64_encode_heap

; int base64_encode_heap(const void* buf, uint32_t len, char** outStr)
; RCX=buf, EDX=len, R8=&outStr
; Returns 0 on success, Win32 error code on failure

CRYPT_STRING_BASE64    EQU 1
CRYPT_STRING_NOCRLF    EQU 40000000h

.data
    b64_msg_ok      db "b64: ok",0
    b64_msg_nul_ok  db "b64: nul ok",0
    b64_msg_nul_bad db "b64: nul MISSING",0
    b64_msg_enter   db "b64: enter",0
    b64_msg_ret     db "b64: ret",0

.code
base64_encode_heap PROC
    sub     rsp, 68h                 ; 32 shadow + ample locals, keep 16-byte alignment
    ; Save inputs in high locals BEFORE logging (RCX/EDX/R8 are volatile)
    mov     [rsp+50h], rcx           ; save buf
    mov     dword ptr [rsp+48h], edx ; save len
    mov     [rsp+58h], r8            ; save &outStr
    lea     rcx, b64_msg_enter
    call    log_cstrln

    ; First call to get required length (in characters, incl NUL)
    mov     rcx, [rsp+50h]           ; pbBinary
    mov     edx, dword ptr [rsp+48h] ; cbBinary
    mov     r8d, CRYPT_STRING_BASE64 or CRYPT_STRING_NOCRLF ; dwFlags
    xor     r9, r9                   ; pszString = NULL
    lea     rax, [rsp+40h]           ; local DWORD for pcchString
    mov     [rsp+20h], rax           ; 5th arg: pcchString
    call    CryptBinaryToStringA
    test    eax, eax
    jnz     b64_have_len
    call    GetLastError
    add     rsp, 68h
    ret

b64_have_len:
    mov     eax, dword ptr [rsp+40h] ; required chars including NUL
    test    eax, eax
    jnz     b64_len_ok
    mov     eax, 1                   ; ensure at least 1 for NUL
b64_len_ok:
    mov     ecx, eax                 ; size in bytes (ANSI chars)
    call    heap_alloc
    test    rax, rax
    jz      b64_oom
    mov     r10, rax                 ; out buffer
    mov     [rsp+30h], r10           ; save out buffer pointer (volatile across calls)

    ; Second call to actually encode
    mov     rcx, [rsp+50h]           ; pbBinary
    mov     edx, dword ptr [rsp+48h] ; cbBinary
    mov     r8d, CRYPT_STRING_BASE64 or CRYPT_STRING_NOCRLF ; dwFlags
    mov     r9, r10                  ; pszString
    lea     rax, [rsp+40h]
    mov     [rsp+20h], rax           ; pcchString
    call    CryptBinaryToStringA
    test    eax, eax
    jnz     b64_ok
    ; failure -> free and return last error
    mov     rcx, r10
    call    heap_free
    call    GetLastError
    add     rsp, 68h
    ret

b64_ok:
    ; store pointer
    mov     r11, [rsp+58h]           ; &outStr
    mov     rax, [rsp+30h]           ; reload saved out buffer pointer
    mov     [r11], rax

    ; Debug: success marker
    lea     rcx, b64_msg_ok
    call    log_cstrln
    jmp     b64_after_dbg
b64_after_dbg:
    lea     rcx, b64_msg_ret
    call    log_cstrln
    xor     eax, eax
    add     rsp, 68h
    ret

b64_oom:
    mov     eax, 8                   ; ERROR_NOT_ENOUGH_MEMORY
    add     rsp, 68h
    ret
base64_encode_heap ENDP

END
