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

PUBLIC net_init
PUBLIC net_cleanup
PUBLIC net_tcp_connect
PUBLIC net_close
PUBLIC net_send
PUBLIC net_recv

AF_INET        EQU 2
SOCK_STREAM    EQU 1
IPPROTO_TCP    EQU 6
SOCKET_ERROR   EQU -1
INVALID_SOCKET EQU -1

.data
    ; Reserve space for WSADATA (>=400 bytes). Use 512 to be safe and 8-byte aligned.
    align 8
wsadata db 512 dup(0)

.code
; int net_init()
; returns 0 on success, else WSAStartup error code in EAX
net_init PROC
    sub     rsp, 28h
    mov     ecx, 0202h           ; MAKEWORD(2,2)
    lea     rdx, wsadata         ; LPWSADATA
    call    WSAStartup
    ; return value already in EAX
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
; Returns 0 on success, else WSAGetLastError() code
net_tcp_connect PROC
    sub     rsp, 48h                 ; 32 shadow + 16 local (sockaddr_in)

    ; Resolve host using gethostbyname(host)
    ; Save parameters
    mov     [rsp+20h], r8            ; save outSock temporarily in local area (won't be overwritten)
    ; call gethostbyname(host)
    ; RCX already = host
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

    ; sockaddr_in at [rsp+30h] (leave [rsp+20h] holding outSock pointer)
    lea     r11, [rsp+30h]
    xor     rax, rax
    mov     qword ptr [r11+0], rax
    mov     qword ptr [r11+8], rax
    mov     word ptr [r11+0], AF_INET
    ; htons(port)
    movzx   ecx, dx                  ; ECX = port (u16)
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

    ; connect(s, &sockaddr, 16)
    mov     rcx, r9                  ; SOCKET
    lea     rdx, [rsp+30h]
    mov     r8d, 16
    call    connect
    test    eax, eax
    jne     ntc_fail_conn

    ; Success: *outSock = s; return 0
    mov     rax, [rsp+20h]           ; outSock*
    mov     [rax], r9                ; store SOCKET
    xor     eax, eax
    add     rsp, 48h
    ret

ntc_fail_conn:
    ; close socket, return last error
    mov     rcx, r9
    call    closesocket
ntc_fail_last:
    call    WSAGetLastError
    add     rsp, 48h
    ret

ntc_fail_host:
    mov     eax, 11001               ; WSAHOST_NOT_FOUND (11001)
    add     rsp, 48h
    ret
net_tcp_connect ENDP

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
