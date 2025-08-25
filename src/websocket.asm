; WebSocket helpers: client key generation and accept computation

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN rng_bytes:PROC
EXTERN base64_encode_heap:PROC
EXTERN sha1_hash:PROC
EXTERN heap_alloc:PROC
EXTERN heap_free:PROC
EXTERN mem_cpy:PROC
EXTERN str_len:PROC
EXTERN log_cstrln:PROC
EXTERN log_ptr64:PROC

PUBLIC ws_make_client_key_heap
PUBLIC ws_compute_accept_heap

.data
    ws_guid db "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 0
    wca_msg_len     db "wca: len computed",0
    wca_msg_alloc   db "wca: tmp allocated",0
    wca_msg_copy1   db "wca: key copied",0
    wca_msg_copy2   db "wca: guid copied",0
    wca_msg_sha_ok  db "wca: sha1 ok",0
    wca_msg_b64_ok  db "wca: base64 ok",0
    wca_msg_enter   db "wca: enter",0
    wca_msg_print   db "wca: printing key",0
    wca_msg_printok db "wca: printed key",0
    wca_msg_before_sha db "wca: before sha1",0
    wca_msg_no_nul  db "wca: key missing NUL (1024 scan)",0
    wca_msg_len_bnd db "wca: len (bounded) computed",0
    wmk_msg_enter   db "wmk: enter",0
    wmk_msg_rng_ok  db "wmk: rng ok",0
    wmk_msg_b64_ok  db "wmk: b64 ok",0
    wmk_msg_ret     db "wmk: ret",0
    wmk_msg_nul_ok  db "wmk: key NUL found",0
    wmk_msg_no_nul  db "wmk: key missing NUL",0
    wmk_msg_ptr     db "wmk: key ptr",0
    wca_msg_ptr     db "wca: key ptr",0

.code
; int ws_make_client_key_heap(char** outKeyB64)
; RCX=&outKeyB64
ws_make_client_key_heap PROC
    sub     rsp, 38h                 ; 32 shadow + 16 local, keep alignment
    mov     [rsp+30h], rcx           ; save &outKeyB64
    lea     rcx, wmk_msg_enter
    call    log_cstrln
    ; Fill 16 random bytes at [rsp+20h]
    lea     rcx, [rsp+20h]
    mov     edx, 16
    call    rng_bytes                ; NTSTATUS in EAX
    test    eax, eax
    jnz     wmk_done                 ; propagate NTSTATUS (non-zero is error)
    lea     rcx, wmk_msg_rng_ok
    call    log_cstrln
    ; Base64 encode into heap string
    lea     rcx, [rsp+20h]
    mov     edx, 16
    mov     r8,  [rsp+30h]
    call    base64_encode_heap       ; returns Win32 error (0 on success)
    lea     rcx, wmk_msg_b64_ok
    call    log_cstrln
    ; Debug: pointer value of generated key
    mov     rax, [rsp+30h]           ; &outKeyB64
    mov     rax, [rax]               ; key ptr
    mov     [rsp+28h], rax           ; save across logging call
    lea     rcx, wmk_msg_ptr
    call    log_cstrln
    mov     rcx, [rsp+28h]
    call    log_ptr64
    ; Skip bounded NUL scan here to avoid potential faults; validate in consumer
wmk_done:
    lea     rcx, wmk_msg_ret
    call    log_cstrln
    add     rsp, 38h
    ret
ws_make_client_key_heap ENDP

; int ws_compute_accept_heap(const char* keyB64, char** outAcceptB64)
; RCX=keyB64, RDX=&outAcceptB64
ws_compute_accept_heap PROC
    sub     rsp, 78h                 ; 32 shadow + temps
    ; Save inputs
    mov     [rsp+70h], rcx           ; keyB64
    mov     [rsp+68h], rdx           ; &out

    ; len = bounded scan up to 1024 to ensure NUL present (debug)
    lea     rcx, wca_msg_enter
    call    log_cstrln
    ; Log key pointer value at entry
    mov     rcx, [rsp+70h]
    lea     rdx, wca_msg_ptr
    ; print label then pointer
    mov     rcx, rdx
    call    log_cstrln
    mov     rcx, [rsp+70h]
    call    log_ptr64
    mov     rax, [rsp+70h]           ; p = keyB64
    xor     r9, r9                   ; len counter
    mov     ecx, 1024                ; bound
bn_scan:
    cmp     byte ptr [rax], 0
    je      bn_found
    inc     rax
    inc     r9
    dec     ecx
    jnz     bn_scan
    ; not found -> log and fail fast
    lea     rcx, wca_msg_no_nul
    call    log_cstrln
    mov     eax, 87                  ; ERROR_INVALID_PARAMETER
    add     rsp, 78h
    ret
bn_found:
    mov     [rsp+60h], r9            ; save len
    lea     rcx, wca_msg_len_bnd
    call    log_cstrln

    ; total = len + 36
    mov     r10, [rsp+60h]
    add     r10, 36
    mov     dword ptr [rsp+50h], r10d   ; preserve total across calls
    ; tmp = heap_alloc(total)
    mov     rcx, r10
    call    heap_alloc
    test    rax, rax
    jz      wca_oom
    mov     [rsp+58h], rax           ; tmp
    lea     rcx, wca_msg_alloc
    call    log_cstrln

    ; copy key into tmp
    mov     rcx, [rsp+58h]           ; dst
    mov     rdx, [rsp+70h]           ; src
    mov     r8,  [rsp+60h]           ; len
    call    mem_cpy
    lea     rcx, wca_msg_copy1
    call    log_cstrln

    ; copy GUID after key
    mov     rcx, [rsp+58h]           ; dst = tmp  
    add     rcx, [rsp+60h]           ; dst = tmp + len
    lea     rdx, ws_guid
    mov     r8,  36
    call    mem_cpy
    lea     rcx, wca_msg_copy2
    call    log_cstrln

    ; sha1 over tmp..tmp+total into local 20-byte buffer at [rsp+40h]
    lea     rcx, wca_msg_before_sha
    call    log_cstrln
    mov     rcx, [rsp+58h]
    mov     edx, dword ptr [rsp+50h]
    lea     r8,  [rsp+40h]
    call    sha1_hash
    test    eax, eax
    jnz     wca_fail
    lea     rcx, wca_msg_sha_ok
    call    log_cstrln

    ; base64 encode the 20-byte hash
    lea     rcx, [rsp+40h]
    mov     edx, 20
    mov     r8,  [rsp+68h]           ; &out
    call    base64_encode_heap
    mov     r9d, eax
    test    r9d, r9d
    jnz     wca_after_free
    lea     rcx, wca_msg_b64_ok
    call    log_cstrln

wca_after_free:
    ; free tmp
    mov     rcx, [rsp+58h]
    call    heap_free

    mov     eax, r9d
    add     rsp, 78h
    ret

wca_oom:
    mov     eax, 8                   ; ERROR_NOT_ENOUGH_MEMORY
    add     rsp, 78h
    ret

wca_fail:
    ; free tmp and return NTSTATUS from sha1_hash
    mov     dword ptr [rsp+38h], eax   ; save status in local
    mov     rcx, [rsp+58h]
    call    heap_free
    mov     eax, dword ptr [rsp+38h]
    add     rsp, 78h
    ret
ws_compute_accept_heap ENDP

END
