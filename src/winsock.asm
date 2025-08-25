; Minimal Winsock layer: net_init / net_cleanup

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN WSAStartup:PROC
EXTERN WSACleanup:PROC
EXTERN gethostbyname:PROC
EXTERN htons:PROC
EXTERN socket:PROC
EXTERN connect:PROC
EXTERN closesocket:PROC
EXTERN WSAGetLastError:PROC
EXTERN send:PROC
EXTERN recv:PROC

EXTERN log_cstrln:PROC
EXTERN log_ptr64:PROC

PUBLIC net_init
PUBLIC net_cleanup
PUBLIC net_tcp_connect
PUBLIC net_close
PUBLIC net_send
PUBLIC net_recv
PUBLIC net_get_last_socket

AF_INET        EQU 2
SOCK_STREAM    EQU 1
IPPROTO_TCP    EQU 6
SOCKET_ERROR   EQU -1
INVALID_SOCKET EQU -1

.data
    ; reserve space for WSADATA (>=400 bytes). Use 512 to be safe and 8-byte aligned.
    align 8
wsadata db 512 dup(0)
    ni_enter db "net_init: enter", 0
    ni_after db "net_init: after WSAStartup rc", 0
    ntc_succ db "net_tcp_connect: success", 0
    ntc_outp db "net_tcp_connect: outSock*", 0
    ntc_outp_val db "net_tcp_connect: *outSock", 0
    ntc_last db "net_tcp_connect: last_socket", 0
    ntc_sock db "net_tcp_connect: socket value", 0
    ntc_outp_in db "net_tcp_connect: outSock* (in)", 0
    ngl_enter db "net_get_last_socket: enter", 0
    ngl_addr  db "net_get_last_socket: &last_socket", 0
    ngl_val   db "net_get_last_socket: last_socket", 0
    align 8
last_socket dq 0

.code
; int net_init()
; returns 0 on success, else WSAStartup error code in EAX
net_init PROC
    sub     rsp, 28h
    lea     rcx, ni_enter
    call    log_cstrln
    mov     ecx, 0202h           ; MAKEWORD(2,2)
    lea     rdx, wsadata         ; LPWSADATA
    call    WSAStartup
    ; return value already in EAX
    lea     rcx, ni_after
    call    log_cstrln
    mov     rcx, rax
    call    log_ptr64
    add     rsp, 28h
    ret
net_init ENDP

; void net_cleanup()
net_cleanup PROC
    sub     rsp, 28h
    call    WSACleanup
    add     rsp, 28h
    ret
net_cleanup ENDP

; int net_tcp_connect(char* host, uint16_t port, uint64_t* outSock)
; RCX=host (C-string), EDX=port (host order), R8=pointer to SOCKET (uint64)
; returns 0 on success, else WSAGetLastError() code
; ALGO NO CUADRA
net_tcp_connect PROC
    sub     rsp, 68h                 ; keep 16-byte alignment (8 misalign + 0x68 = 0)
    mov     qword ptr [rsp+20h], rbx ; save non-volatile RBX in shadow space

    ; resolve host using gethostbyname(host)
    ; save parameters (place beyond callee shadow space)
    mov     qword ptr [rsp+50h], rcx  ; save host pointer
    mov     qword ptr [rsp+60h], r8  ; save outSock pointer (debug)
    mov     rbx, r8                  ; keep outSock* in RBX across calls
    ; preserve incoming port (EDX) early for later htons
    movzx   eax, dx
    mov     dword ptr [rsp+58h], eax
    ; debug: show incoming outSock*
    lea     rcx, ntc_outp_in
    call    log_cstrln
    mov     rcx, qword ptr [rsp+60h]
    call    log_ptr64
    ; proceed to real implementation
    jmp     ntc_real
ntc_real:
    ; call gethostbyname(host)
    mov     rcx, qword ptr [rsp+50h] ; restore host
    call    gethostbyname
    test    rax, rax
    jz      ntc_fail_host

    ; hostent layout (x64):
    ; +0  char*  h_name
    ; +8  char** h_aliases
    ; +16 short  h_addrtype
    ; +18 short  h_length
    ; +24 char** h_addr_list
    mov     r9, qword ptr [rax+24]   ; r9 = h_addr_list
    test    r9, r9
    jz      ntc_fail_host
    mov     r9, qword ptr [r9]       ; r9 = first address (in_addr*)
    test    r9, r9
    jz      ntc_fail_host
    mov     r10d, dword ptr [r9]     ; r10d = IPv4 address (network order)

    ; sockaddr_in at [rsp+40h]
    lea     r11, [rsp+40h]
    xor     rax, rax
    mov     qword ptr [r11+0], rax
    mov     qword ptr [r11+8], rax
    mov     word ptr [r11+0], AF_INET
    ; htons(port)
    movzx   ecx, word ptr [rsp+58h]  ; ECX = saved port (u16)
    call    htons
    mov     word ptr [r11+2], ax     ; sin_port
    mov     dword ptr [r11+4], r10d  ; sin_addr

    ; socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    mov     ecx, AF_INET
    mov     edx, SOCK_STREAM
    mov     r8d, IPPROTO_TCP
    call    socket
    mov     r9, rax                  ; r9 = SOCKET
    cmp     r9, -1
    je      ntc_fail_last
    ; debug: log socket value returned by socket()
    lea     rcx, ntc_sock
    call    log_cstrln
    mov     rcx, r9
    call    log_ptr64
    ; write socket value to *outSock immediately after socket()
    mov     rax, qword ptr [rsp+60h]
    mov     qword ptr [rax], r9
    ; debug: verify *outSock after immediate write
    mov     rcx, qword ptr [rax]
    call    log_ptr64

    ; connect(s, &sockaddr, 16)
    ; Save SOCKET to local (use [rsp+30h], outside sockaddr [40h..5Fh])
    mov     qword ptr [rsp+30h], r9   ; save SOCKET in local slot
    mov     rcx, qword ptr [rsp+30h] ; SOCKET
    lea     rdx, [rsp+40h]
    mov     r8d, 16
    call    connect
    test    eax, eax
    jne     ntc_fail_conn

    ; Success: *outSock = s; return 0 (no extra logging to avoid clobber issues)
    mov     rax, qword ptr [rsp+60h] ; outSock*
    mov     r10, qword ptr [rsp+30h] ; SOCKET
    mov     qword ptr [rax], r10     ; store SOCKET
    mov     qword ptr [last_socket], r10
    ; debug: verify stored values
    lea     rcx, ntc_outp
    call    log_cstrln
    mov     rcx, qword ptr [rsp+60h] ; outSock* address
    call    log_ptr64
    mov     rax, qword ptr [rsp+60h]
    mov     rcx, qword ptr [rax]     ; *outSock
    call    log_ptr64
    mov     rcx, qword ptr [last_socket]
    call    log_ptr64
    ; extra: read back last_socket again to ensure it's set
    mov     rcx, qword ptr [last_socket]
    call    log_ptr64
    xor     eax, eax
    mov     rbx, qword ptr [rsp+20h]
    add     rsp, 68h
    ret

ntc_fail_conn:
    ; close socket, return last error
    mov     rcx, r9
    call    closesocket
ntc_fail_last:
    call    WSAGetLastError
    mov     rbx, qword ptr [rsp+20h]
    add     rsp, 68h
    ret

ntc_fail_host:
    mov     eax, 11001               ; WSAHOST_NOT_FOUND (11001)
    mov     rbx, qword ptr [rsp+20h]
    add     rsp, 68h
    ret
net_tcp_connect ENDP

; uint64_t net_get_last_socket()
; returns the last socket stored by net_tcp_connect (debug helper)
net_get_last_socket PROC
    sub     rsp, 28h
    lea     rcx, ngl_enter
    call    log_cstrln
    lea     rcx, last_socket
    call    log_ptr64
    lea     rcx, ngl_val
    call    log_cstrln
    mov     rcx, qword ptr [last_socket]
    call    log_ptr64
    mov     rax, [last_socket]
    add     rsp, 28h
    ret
net_get_last_socket ENDP

; int net_close(uint64_t s)
; RCX=SOCKET, returns 0 on success else WSAGetLastError()
net_close PROC
    sub     rsp, 28h
    call    closesocket
    test    eax, eax
    je      nc_ok
    call    WSAGetLastError
    add     rsp, 28h
    ret
nc_ok:
    xor     eax, eax
    add     rsp, 28h
    ret
net_close ENDP

; int net_send(uint64_t s, const void* buf, uint32_t len)
; Returns number of bytes sent, or negative WSA error code
net_send PROC
    sub     rsp, 28h
    ; send(s, buf, len, 0)
    ; RCX=s, RDX=buf, R8=len
    xor     r9d, r9d
    call    send
    cmp     eax, 0
    jge     ns_ok
    ; error -> return -WSAGetLastError()
    call    WSAGetLastError
    neg     eax
    add     rsp, 28h
    ret
ns_ok:
    add     rsp, 28h
    ret
net_send ENDP

; int net_recv(uint64_t s, void* buf, uint32_t len)
; Returns number of bytes received, 0 on orderly close, or negative WSA error code
net_recv PROC
    sub     rsp, 28h
    ; recv(s, buf, len, 0)
    xor     r9d, r9d
    call    recv
    cmp     eax, 0
    jge     nr_done
    call    WSAGetLastError
    neg     eax
nr_done:
    add     rsp, 28h
    ret
net_recv ENDP

END
