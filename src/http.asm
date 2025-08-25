; HTTP helpers: build WebSocket client handshake request string

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN str_len:PROC
EXTERN mem_cpy:PROC
EXTERN heap_alloc:PROC
EXTERN heap_free:PROC
EXTERN log_cstrln:PROC
EXTERN log_ptr64:PROC

PUBLIC http_ws_request_heap

.data
    http_get      db "GET ",0
    http_http11   db " HTTP/1.1",13,10,0
    hdr_host      db "Host: ",0
    hdr_upgrade   db "Upgrade: websocket",13,10,0
    hdr_conn      db "Connection: Upgrade",13,10,0
    hdr_version   db "Sec-WebSocket-Version: 13",13,10,0
    hdr_key       db "Sec-WebSocket-Key: ",0
    http_crlf     db 13,10,0
    http_crlf2    db 13,10,13,10,0
    ; debug strings
    hwr_msg_enter db "hwr: enter",0
    hwr_msg_alloc db "hwr: alloc ok",0
    hwr_msg_out   db "hwr: out ptr",0
    hwr_msg_ret   db "hwr: ret",0
    hwr_msg_oom   db "hwr: oom",0
    hwr_msg_req   db "hwr: request",0

.code
; int http_ws_request_heap(const char* host, const char* path, const char* keyB64, char** outStr)
; RCX=host, RDX=path, R8=keyB64, R9=&outStr
http_ws_request_heap PROC
    sub     rsp, 78h                 ; 32 shadow + larger locals, keep alignment
    mov     [rsp+70h], rbx           ; save non-volatile rbx
    ; Save inputs BEFORE any calls (RCX,RDX,R8,R9 are volatile)
    mov     [rsp+50h], rcx           ; host
    mov     [rsp+48h], rdx           ; path
    mov     [rsp+40h], r8            ; key
    mov     [rsp+38h], r9            ; &out
    ; debug enter
    lea     rcx, hwr_msg_enter
    call    log_cstrln

    ; Compute lengths
    mov     rcx, [rsp+48h]           ; path
    call    str_len
    mov     [rsp+30h], rax           ; pathLen

    mov     rcx, [rsp+50h]           ; host
    call    str_len
    mov     [rsp+28h], rax           ; hostLen

    mov     rcx, [rsp+40h]           ; key
    call    str_len
    mov     [rsp+20h], rax           ; keyLen

    ; Compute constant lengths
    lea     rcx, http_get
    call    str_len
    mov     r10, rax
    lea     rcx, http_http11
    call    str_len
    add     r10, rax
    lea     rcx, hdr_host
    call    str_len
    add     r10, rax
    lea     rcx, hdr_upgrade
    call    str_len
    add     r10, rax
    lea     rcx, hdr_conn
    call    str_len
    add     r10, rax
    lea     rcx, hdr_version
    call    str_len
    add     r10, rax
    lea     rcx, hdr_key
    call    str_len
    add     r10, rax
    lea     rcx, http_crlf
    call    str_len
    add     r10, rax
    lea     rcx, http_crlf2
    call    str_len
    add     r10, rax

    ; total = consts + hostLen + pathLen + keyLen + 1 (NUL)
    mov     rax, [rsp+30h]
    add     r10, rax
    mov     rax, [rsp+28h]
    add     r10, rax
    mov     rax, [rsp+20h]
    add     r10, rax
    inc     r10                      ; +1 for NUL

    ; Allocate
    mov     rcx, r10
    call    heap_alloc
    test    rax, rax
    jz      hwr_oom
    mov     r11, rax                 ; dst cursor = base
    mov     [rsp+60h], r11           ; save base (high local)
    mov     [rsp+58h], r11           ; save current cursor
    ; debug alloc ok and base ptr
    lea     rcx, hwr_msg_alloc
    call    log_cstrln
    mov     r11, [rsp+58h]
    mov     rcx, r11
    call    log_ptr64

    ; "GET "
    lea     rcx, http_get
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, http_get
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax
    ; debug after first copy: base and cursor
    lea     rcx, hwr_msg_req
    call    log_cstrln
    mov     rcx, [rsp+60h]
    call    log_ptr64
    mov     rcx, [rsp+58h]
    call    log_ptr64

    ; path
    mov     rcx, [rsp+48h]
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    mov     rdx, [rsp+48h]
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; " HTTP/1.1\r\n"
    lea     rcx, http_http11
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, http_http11
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; "Host: "
    lea     rcx, hdr_host
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, hdr_host
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; host
    mov     rcx, [rsp+50h]
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    mov     rdx, [rsp+50h]
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; CRLF
    lea     rcx, http_crlf
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, http_crlf
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; Upgrade header
    lea     rcx, hdr_upgrade
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, hdr_upgrade
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; Connection header
    lea     rcx, hdr_conn
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, hdr_conn
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; Sec-WebSocket-Version header
    lea     rcx, hdr_version
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, hdr_version
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; Sec-WebSocket-Key header
    lea     rcx, hdr_key
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, hdr_key
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; key
    mov     rcx, [rsp+40h]
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    mov     rdx, [rsp+40h]
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; CRLF CRLF
    lea     rcx, http_crlf2
    call    str_len
    mov     rbx, rax
    mov     r11, [rsp+58h]
    mov     rcx, r11
    lea     rdx, http_crlf2
    mov     r8,  rbx
    call    mem_cpy
    mov     rax, [rsp+58h]
    add     rax, rbx
    mov     [rsp+58h], rax

    ; NUL terminate
    mov     r11, [rsp+58h]
    mov     byte ptr [r11], 0

    ; out = base pointer saved in [rsp+60h]
    mov     rdx, [rsp+60h]
    mov     rax, [rsp+38h]
    mov     [rax], rdx
    ; debug out ptr
    lea     rcx, hwr_msg_out
    call    log_cstrln
    mov     rcx, [rsp+60h]
    call    log_ptr64
    ; dump the request string for verification
    lea     rcx, hwr_msg_req
    call    log_cstrln
    mov     rcx, [rsp+60h]
    call    log_cstrln
    xor     eax, eax
    ; debug ret
    lea     rcx, hwr_msg_ret
    call    log_cstrln
    mov     rbx, [rsp+70h]
    add     rsp, 78h
    ret

hwr_oom:
    lea     rcx, hwr_msg_oom
    call    log_cstrln
    mov     eax, 8
    mov     rbx, [rsp+70h]
    add     rsp, 78h
    ret
http_ws_request_heap ENDP

END
