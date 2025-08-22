; Minimal Winsock layer: net_init / net_cleanup

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN WSAStartup:PROC
EXTERN WSACleanup:PROC

PUBLIC net_init
PUBLIC net_cleanup

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

END
