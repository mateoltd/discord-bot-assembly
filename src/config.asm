; Configuration helpers: read environment variables into heap-allocated strings

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN GetEnvironmentVariableA:PROC
EXTERN GetLastError:PROC
EXTERN CreateFileA:PROC
EXTERN GetFileSizeEx:PROC
EXTERN ReadFile:PROC
EXTERN CloseHandle:PROC

EXTERN heap_alloc:PROC
EXTERN heap_free:PROC

PUBLIC config_env_get_heap
PUBLIC config_file_get_heap
PUBLIC config_load_token_heap

GENERIC_READ         EQU 80000000h
FILE_SHARE_READ      EQU 1
OPEN_EXISTING        EQU 3
INVALID_HANDLE_VALUE EQU -1

.data
    token_env_name      db "DISCORD_BOT_TOKEN", 0
    token_file_env_name db "DISCORD_TOKEN_FILE", 0
    token_default_path  db "config\\token.txt", 0

.code
; int config_env_get_heap(const char* name, char** outStr)
; RCX = name, RDX = &outStr
; On success: returns 0, *outStr points to heap-allocated NUL-terminated string. Caller must heap_free.
; On failure: returns Win32 error code (e.g., 203 ERROR_ENVVAR_NOT_FOUND)
config_env_get_heap PROC
    sub     rsp, 48h                  ; 32 shadow + 16 locals (name,out, size)

    ; Save inputs
    mov     [rsp+20h], rcx            ; save name
    mov     [rsp+28h], rdx            ; save &outStr

    ; size = GetEnvironmentVariableA(name, NULL, 0)
    mov     rcx, [rsp+20h]            ; name
    xor     rdx, rdx                  ; lpBuffer = NULL
    xor     r8d, r8d                  ; nSize = 0
    call    GetEnvironmentVariableA
    test    eax, eax
    jnz     cee_have_size
    ; failure: return GetLastError()
    call    GetLastError
    add     rsp, 48h
    ret

cee_have_size:
    mov     dword ptr [rsp+30h], eax  ; save required size (bytes)
    mov     ecx, eax                   ; size
    call    heap_alloc
    test    rax, rax
    jz      cee_fail_oom
    mov     r9, rax                    ; buffer

    ; Read into buffer
    mov     rcx, [rsp+20h]             ; name
    mov     rdx, r9                    ; lpBuffer
    mov     r8d, dword ptr [rsp+30h]   ; nSize
    call    GetEnvironmentVariableA
    test    eax, eax
    jnz     cee_success

    ; Read failed: free and return last error
    mov     rcx, r9
    call    heap_free
    call    GetLastError
    add     rsp, 48h
    ret

cee_success:
    ; *outStr = buffer
    mov     r10, [rsp+28h]            ; &outStr
    mov     [r10], r9
    xor     eax, eax
    add     rsp, 48h
    ret

cee_fail_oom:
    mov     eax, 8                    ; ERROR_NOT_ENOUGH_MEMORY
    add     rsp, 48h
    ret
config_env_get_heap ENDP

; int config_file_get_heap(const char* path, char** outStr)
; Reads entire file as ANSI text, trims trailing CR/LF, NUL-terminates, heap-allocates buffer.
config_file_get_heap PROC
    sub     rsp, 58h                  ; 32 shadow + 16 locals + 8 for size64
    ; Save inputs in high locals to avoid clobbering extra call args
    mov     [rsp+40h], rcx            ; save path
    mov     [rsp+48h], rdx            ; save &out

    ; h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)
    mov     rcx, [rsp+40h]
    mov     rdx, GENERIC_READ
    mov     r8d, FILE_SHARE_READ
    xor     r9, r9                     ; lpSecurityAttributes = NULL (4th)
    mov     dword ptr [rsp+20h], OPEN_EXISTING   ; 5th: dwCreationDisposition
    mov     dword ptr [rsp+28h], 0               ; 6th: dwFlagsAndAttributes
    mov     qword ptr [rsp+30h], 0               ; 7th: hTemplateFile
    call    CreateFileA
    mov     r10, rax
    cmp     r10, INVALID_HANDLE_VALUE
    jne     cfh_have
    call    GetLastError
    add     rsp, 58h
    ret
cfh_have:
    ; GetFileSizeEx(h, &size)
    lea     rdx, [rsp+38h]
    mov     rcx, r10
    call    GetFileSizeEx
    test    eax, eax
    jz      cfh_fail_last_close
    mov     r11, [rsp+38h]            ; size (int64)
    test    r11, r11
    jz      cfh_fail_last_close
    ; Cap size to e.g. 4MB to be safe
    mov     rax, 400000h
    cmp     r11, rax
    jbe     cfh_size_ok
    mov     r11, rax
cfh_size_ok:
    ; alloc size+1
    mov     rcx, r11
    inc     rcx
    call    heap_alloc
    test    rax, rax
    jz      cfh_oom_close
    mov     r9, rax                   ; buf

    ; ReadFile(h, buf, (DWORD)size, &read, NULL)
    mov     rcx, r10
    mov     rdx, r9
    mov     r8d, r11d
    lea     r9, [rsp+30h]             ; DWORD read
    mov     qword ptr [rsp+20h], 0    ; lpOverlapped (reuse local area)
    call    ReadFile
    test    eax, eax
    jz      cfh_fail_read
    ; NUL-terminate and trim CR/LF
    mov     eax, dword ptr [rsp+30h]  ; read
    mov     byte ptr [r9+rax], 0
    test    eax, eax
    jz      cfh_done_ok
    ; trim loop
cfh_trim:
    mov     edx, eax
    dec     edx
    mov     bl, byte ptr [r9+rdx]
    cmp     bl, 13
    je      cfh_trim_cr
    cmp     bl, 10
    je      cfh_trim_lf
    jmp     cfh_done_ok
cfh_trim_cr:
    mov     byte ptr [r9+rdx], 0
    mov     eax, edx
    jmp     cfh_trim
cfh_trim_lf:
    mov     byte ptr [r9+rdx], 0
    mov     eax, edx
    jmp     cfh_trim

cfh_done_ok:
    ; Close and return buffer
    mov     rcx, r10
    call    CloseHandle
    mov     r10, [rsp+48h]
    mov     [r10], r9
    xor     eax, eax
    add     rsp, 58h
    ret

cfh_fail_read:
    ; free buf, close, return last error
    mov     rcx, r9
    call    heap_free
    mov     rcx, r10
    call    CloseHandle
    call    GetLastError
    add     rsp, 58h
    ret

cfh_oom_close:
    mov     rcx, r10
    call    CloseHandle
    mov     eax, 8
    add     rsp, 58h
    ret

cfh_fail_last_close:
    mov     rcx, r10
    call    CloseHandle
    call    GetLastError
    add     rsp, 58h
    ret
config_file_get_heap ENDP

; int config_load_token_heap(char** outStr)
; RCX = &outStr
; Tries env var DISCORD_BOT_TOKEN, then config\\token.txt (cwd-relative)
config_load_token_heap PROC
    sub     rsp, 28h
    ; Save &outStr
    mov     [rsp+20h], rcx

    ; Try environment variable first
    lea     rcx, token_env_name
    lea     rdx, [rsp+18h]            ; temp storage for pointer
    call    config_env_get_heap
    test    eax, eax
    jz      clt_success

    ; Optional override path via DISCORD_TOKEN_FILE
    lea     rcx, token_file_env_name
    lea     rdx, [rsp+10h]            ; temp path pointer
    call    config_env_get_heap
    test    eax, eax
    jnz     clt_default_file
    ; Have path -> read file
    mov     rcx, [rsp+10h]
    lea     rdx, [rsp+18h]
    call    config_file_get_heap
    mov     r11d, eax
    ; free path buffer
    mov     rcx, [rsp+10h]
    call    heap_free
    test    r11d, r11d
    jz      clt_success
    ; else continue to default

clt_default_file:
    ; Fallback to config\token.txt
    lea     rcx, token_default_path
    lea     rdx, [rsp+18h]
    call    config_file_get_heap
    test    eax, eax
    jnz     clt_fail                  ; propagate last error

clt_success:
    ; *outStr = temp
    mov     r10, [rsp+20h]            ; &outStr
    mov     rax, [rsp+18h]            ; temp ptr
    mov     [r10], rax
    xor     eax, eax
    add     rsp, 28h
    ret

clt_fail:
    ; return error in EAX from last call
    add     rsp, 28h
    ret
config_load_token_heap ENDP

END
