; SHA-1 helper using Windows CNG (bcrypt)

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN BCryptOpenAlgorithmProvider:PROC
EXTERN BCryptGetProperty:PROC
EXTERN BCryptCreateHash:PROC
EXTERN BCryptHashData:PROC
EXTERN BCryptFinishHash:PROC
EXTERN BCryptDestroyHash:PROC
EXTERN BCryptCloseAlgorithmProvider:PROC

EXTERN heap_alloc:PROC
EXTERN heap_free:PROC

PUBLIC sha1_hash

; NTSTATUS sha1_hash(const void* buf, uint32_t len, uint8_t* out20)
; RCX=buf, EDX=len, R8=out20 (must be >=20 bytes)

.code
.data
    wSHA1       dw 'S','H','A','1',0
    wObjLen     dw 'O','b','j','e','c','t','L','e','n','g','t','h',0
    wHashLen    dw 'H','a','s','h','D','i','g','e','s','t','L','e','n','g','t','h',0

.code
sha1_hash PROC
    sub     rsp, 78h                  ; 32 shadow + locals, keep 16-byte alignment for calls
    ; Save inputs (use high locals away from arg spill slots)
    mov     [rsp+70h], rcx            ; buf
    mov     dword ptr [rsp+6Ch], edx  ; len
    mov     [rsp+68h], r8             ; out20

    ; phAlg at [rsp+50h], hHash at [rsp+48h]
    lea     rcx, [rsp+50h]            ; phAlg (store handle at [rsp+50h])
    lea     rdx, wSHA1                ; alg id L"SHA1"
    xor     r8, r8                    ; implementation = NULL
    xor     r9d, r9d                  ; flags = 0
    call    BCryptOpenAlgorithmProvider
    test    eax, eax
    jnz     sha_fail                  ; Non-zero NTSTATUS indicates failure

    ; Query BCRYPT_OBJECT_LENGTH -> objLen (DWORD at [rsp+40h])
    mov     rcx, [rsp+50h]            ; hAlg
    lea     rdx, wObjLen
    lea     r8, [rsp+40h]             ; pbOutput -> we'll store DWORD here
    mov     r9d, 4                    ; cbOutput
    lea     rax, [rsp+38h]            ; pcbResult (DWORD)
    mov     [rsp+20h], rax
    mov     dword ptr [rsp+28h], 0    ; dwFlags = 0
    call    BCryptGetProperty
    test    eax, eax
    jnz     sha_cleanup_alg

    ; Query BCRYPT_HASH_LENGTH -> hashLen (DWORD at [rsp+30h])
    mov     rcx, [rsp+50h]            ; hAlg
    lea     rdx, wHashLen
    lea     r8, [rsp+30h]
    mov     r9d, 4
    lea     rax, [rsp+38h]
    mov     [rsp+20h], rax
    mov     dword ptr [rsp+28h], 0
    call    BCryptGetProperty
    test    eax, eax
    jnz     sha_cleanup_alg

    ; Validate hashLen == 20
    mov     eax, dword ptr [rsp+30h]
    cmp     eax, 20
    je      sha_len_ok
    mov     eax, 0C000000Dh           ; STATUS_INVALID_PARAMETER
    jmp     sha_cleanup_alg
sha_len_ok:

    ; Allocate hash object buffer of objLen
    mov     ecx, dword ptr [rsp+40h]
    call    heap_alloc
    test    rax, rax
    jz      sha_oom
    mov     [rsp+58h], rax            ; save pHashObject at [rsp+58h]

    ; Create hash
    mov     rcx, [rsp+50h]            ; hAlg
    lea     rdx, [rsp+48h]            ; &hHash
    mov     r8, [rsp+58h]             ; pbHashObject
    mov     r9d, dword ptr [rsp+40h]  ; cbHashObject
    xor     eax, eax
    mov     [rsp+20h], rax            ; pbSecret = NULL
    mov     dword ptr [rsp+28h], 0    ; cbSecret = 0
    mov     dword ptr [rsp+30h], 0    ; dwFlags = 0
    call    BCryptCreateHash
    test    eax, eax
    jnz     sha_free_obj

    ; Hash data
    mov     rcx, [rsp+48h]            ; hHash
    mov     rdx, [rsp+70h]            ; buf
    mov     r8d, dword ptr [rsp+6Ch]  ; len
    xor     r9d, r9d
    call    BCryptHashData
    test    eax, eax
    jnz     sha_destroy_hash

    ; Finish hash
    mov     rcx, [rsp+48h]
    mov     rdx, [rsp+68h]            ; out20
    mov     r8d, 20
    xor     r9d, r9d
    call    BCryptFinishHash
    test    eax, eax
    jnz     sha_destroy_hash

    ; Success -> cleanup and return 0
    xor     eax, eax
    jmp     sha_cleanup_all

sha_oom:
    mov     eax, 0C000009Ah           ; STATUS_INSUFFICIENT_RESOURCES
    jmp     sha_cleanup_alg

sha_destroy_hash:
    mov     rcx, [rsp+48h]
    call    BCryptDestroyHash
sha_free_obj:
    mov     rcx, [rsp+58h]
    test    rcx, rcx
    jz      sha_cleanup_alg
    call    heap_free
sha_cleanup_alg:
    mov     rcx, [rsp+50h]
    test    rcx, rcx
    jz      sha_fail
    xor     r9d, r9d
    call    BCryptCloseAlgorithmProvider
sha_fail:
    ; return EAX with error
    add     rsp, 78h
    ret

sha_cleanup_all:
    ; destroy hash, free obj, close alg then return success
    mov     rcx, [rsp+48h]
    call    BCryptDestroyHash
    mov     rcx, [rsp+58h]
    call    heap_free
    mov     rcx, [rsp+50h]
    xor     r9d, r9d
    call    BCryptCloseAlgorithmProvider
    add     rsp, 78h
    ret
sha1_hash ENDP

END
