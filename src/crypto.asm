; Crypto helpers: RNG via BCryptGenRandom (system-preferred RNG)

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN BCryptGenRandom:PROC

PUBLIC rng_bytes

.code
; NTSTATUS rng_bytes(uint8_t* buf, uint32_t len)
; RCX=buf, EDX=len. Returns NTSTATUS (0 = STATUS_SUCCESS)
rng_bytes PROC
    sub     rsp, 28h
    ; Save inputs
    mov     r10, rcx           ; buf
    mov     r11d, edx          ; len

    ; BCryptGenRandom(NULL, buf, len, 2)
    xor     ecx, ecx           ; hAlgorithm = NULL
    mov     rdx, r10           ; pbBuffer = buf
    mov     r8d, r11d          ; cbBuffer = len
    mov     r9d, 2             ; BCRYPT_USE_SYSTEM_PREFERRED_RNG
    call    BCryptGenRandom
    add     rsp, 28h
    ret
rng_bytes ENDP

END
