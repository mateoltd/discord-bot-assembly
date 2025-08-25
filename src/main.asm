; Minimal MASM x64 entry point to verify toolchain

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN ExitProcess:PROC
EXTERN log_cstrln:PROC
EXTERN log_ptr64:PROC
EXTERN net_init:PROC
EXTERN net_cleanup:PROC
EXTERN config_load_token_heap:PROC
EXTERN heap_free:PROC
EXTERN net_tcp_connect:PROC
EXTERN net_close:PROC
EXTERN ws_make_client_key_heap:PROC
EXTERN ws_compute_accept_heap:PROC
EXTERN http_ws_request_heap:PROC
EXTERN str_len:PROC
EXTERN net_send:PROC
EXTERN net_recv:PROC
EXTERN net_get_last_socket:PROC

.data
msg_boot    db "Discord ASM bot bootstrap OK", 0
msg_wsok    db "Winsock init OK", 0
msg_wsfail  db "Winsock init FAILED", 0
msg_cfg_ok  db "Config: DISCORD_BOT_TOKEN loaded", 0
msg_cfg_nf  db "Config: DISCORD_BOT_TOKEN not found", 0
host_discord db "discord.com", 0
msg_tcp_ok  db "TCP connect to discord.com:443 OK", 0
msg_tcp_fail db "TCP connect to discord.com:443 FAILED", 0
; WebSocket handshake test constants
ws_host     db "gateway.discord.gg", 0
ws_path     db "/?v=10&encoding=json", 0
msg_ws_req  db "WebSocket handshake request:", 0
msg_debug_start db "Debug: Starting WebSocket test", 0
msg_debug_before_wmk db "Debug: before wmk", 0
msg_debug_after_wmk  db "Debug: after wmk", 0
msg_debug_key   db "Debug: Generated client key", 0
msg_debug_keylen_ok db "Debug: Key str_len OK", 0
msg_debug_key_nul_ok db "Debug: Key NUL found (bounded)", 0
msg_debug_key_no_nul db "Debug: Key missing NUL (bounded)", 0
msg_debug_before_wca db "Debug: before wca", 0
msg_debug_after_wca  db "Debug: after wca", 0
msg_debug_accept db "Debug: Computed accept key", 0
msg_debug_config db "Debug: About to load config", 0
msg_debug_config_done db "Debug: Config loading done", 0
msg_debug_tcp db "Debug: About to test TCP", 0
msg_debug_tcp_done db "Debug: TCP test done", 0
msg_key_ptr_ok  db "Debug: key ptr NON-NULL", 0
msg_key_ptr_null db "Debug: key ptr NULL", 0
msg_ws_net_start db "Debug: WS net send test", 0
msg_ws_conn_fail db "Debug: WS connect failed", 0
msg_ws_conn_ok   db "Debug: WS connect ok", 0
msg_ws_send_fail db "Debug: WS send failed", 0
msg_ws_send_ok   db "Debug: WS send ok", 0
msg_ws_recv_fail db "Debug: WS recv failed", 0
msg_ws_recv_ok   db "Debug: WS recv ok", 0
msg_ws_resp      db "WebSocket handshake response:", 0
msg_ws_init_rc   db "Debug: WS init rc:", 0
msg_ws_conn_rc   db "Debug: WS connect rc:", 0
msg_req_len      db "Debug: WS req length:", 0
msg_send_rc      db "Debug: WS send rc:", 0

    ; Plain HTTP test to validate networking
    msg_http_test    db "Debug: HTTP GET example.com test", 0
http_host        db "example.com", 0
http_req         db "GET / HTTP/1.1", 13,10, "Host: example.com", 13,10, "Connection: close", 13,10, 13,10, 0
msg_http_conn_ok db "HTTP: connect ok", 0
msg_http_conn_fail db "HTTP: connect failed", 0
msg_http_send_rc db "HTTP: send rc", 0
msg_http_recv_rc db "HTTP: recv rc", 0
msg_http_resp    db "HTTP response:", 0
msg_http_init    db "HTTP: calling net_init", 0
msg_http_init_ok db "HTTP: net_init returned", 0
msg_http_connecting db "HTTP: calling net_tcp_connect", 0
msg_http_conn_rc db "HTTP: connect rc", 0
msg_http_sock    db "HTTP: socket ptr", 0
msg_http_skip_init db "HTTP: SKIP net_init (pointer test)", 0

    align 8
g_http_socket dq 0

    ; Cleanup debug markers
    msg_ws_cleanup_enter db "Debug: ws_after_net enter", 0
    msg_ws_cleanup_close db "Debug: ws_after_net close if any", 0
    msg_ws_cleanup_done  db "Debug: ws_after_net cleanup done", 0
    msg_free_req     db "Debug: freeing request ptr:", 0
    msg_free_acc     db "Debug: freeing accept ptr:", 0
    msg_free_key     db "Debug: freeing key ptr:", 0
    msg_reach_http   db "Debug: reached ws_test_done -> HTTP test", 0
    msg_ws_before_skip db "Debug: before skip to ws_after_net", 0

align 8
respbuf db 2048 dup(0)

.code
main PROC
    ; Reserve shadow space (32) + extra locals (0x38) = 0x68. Keeps 16-byte alignment.
    sub     rsp, 68h

    ; Zero-init local pointer slots used throughout (socket, request, accept, key)
    mov     qword ptr [rsp+58h], 0     ; SOCKET storage (moved out of shadow space)
    mov     qword ptr [rsp+40h], 0     ; request ptr
    mov     qword ptr [rsp+48h], 0     ; accept ptr
    mov     qword ptr [rsp+50h], 0     ; key ptr

    ; log_cstrln("Discord ASM bot bootstrap OK")
    lea     rcx, msg_boot
    call    log_cstrln

    ; TEMP DEBUG: Skip Winsock init/TCP and run only WebSocket self-test
    jmp     ws_selftest

    ; Debug: about to load config
    lea     rcx, msg_debug_config
    call    log_cstrln

    ; TEMPORARILY BYPASS CONFIG LOADING TO ISOLATE CRASH
    ; Load bot token via config (env -> DISCORD_TOKEN_FILE -> config/token.txt)
    ; lea     rcx, [rsp+50h]         ; &outStr temp storage (outside home space)
    ; call    config_load_token_heap
    ; test    eax, eax
    ; jnz     no_token
    ; success -> log and free
    ; lea     rcx, msg_cfg_ok
    ; call    log_cstrln
    ; mov     rcx, [rsp+50h]
    ; call    heap_free
    ; jmp     after_cfg

    ; Simulate no token found
    lea     rcx, msg_cfg_nf
    call    log_cstrln

after_cfg:
    ; Debug: config done
    lea     rcx, msg_debug_config_done
    call    log_cstrln

    ; Debug: about to test TCP
    lea     rcx, msg_debug_tcp
    call    log_cstrln

    ; Quick TCP connect test to discord.com:443 (no TLS yet)
    lea     rcx, host_discord      ; host
    mov     edx, 443               ; port
    lea     r8,  [rsp+58h]         ; &SOCKET storage (designated socket local)
    call    net_tcp_connect
    ; immediate post-call: log *outSock value written by callee
    lea     rcx, msg_http_sock
    call    log_cstrln
    mov     rcx, [rsp+58h]
    call    log_ptr64
    test    eax, eax
    jnz     tcp_fail
    ; success -> log and close
    lea     rcx, msg_tcp_ok
    call    log_cstrln
    mov     rcx, [rsp+58h]
    call    net_close
    
    ; Debug: TCP success done
    lea     rcx, msg_debug_tcp_done
    call    log_cstrln
    jmp     after_tcp

tcp_fail:
    lea     rcx, msg_tcp_fail
    call    log_cstrln
    
    ; Debug: TCP test done
    lea     rcx, msg_debug_tcp_done
    call    log_cstrln

after_tcp:
ws_selftest:
    ; --- Temporary self-test: build and log WebSocket handshake request ---
    ; Debug: About to generate client key
    lea     rcx, msg_debug_start
    call    log_cstrln
    
    ; Generate client key (Base64 string on heap) -> [rsp+50h]
    lea     rcx, msg_debug_before_wmk
    call    log_cstrln
    lea     rcx, [rsp+50h]
    call    ws_make_client_key_heap
    test    eax, eax
    jnz     ws_test_done
    lea     rcx, msg_debug_after_wmk
    call    log_cstrln
    
    ; Debug: key generated successfully
    lea     rcx, msg_debug_key
    call    log_cstrln

    ; Check pointer validity (NULL/non-NULL) before using it
    mov     rax, [rsp+50h]
    test    rax, rax
    jnz     key_ptr_nonnull
    lea     rcx, msg_key_ptr_null
    call    log_cstrln
    jmp     ws_test_done
key_ptr_nonnull:
    lea     rcx, msg_key_ptr_ok
    call    log_cstrln
    ; Print the actual key pointer value for verification
    mov     rcx, [rsp+50h]
    call    log_ptr64

    ; Compute accept key from client key -> [rsp+48h]
    lea     rcx, msg_debug_before_wca
    call    log_cstrln
    mov     rcx, [rsp+50h]
    lea     rdx, [rsp+48h]
    call    ws_compute_accept_heap
    ; Log return code from ws_compute_accept_heap
    lea     r11, msg_debug_after_wca  ; reuse label as context marker
    mov     rcx, r11
    call    log_cstrln
    mov     rcx, rax                  ; print EAX as pointer for quick debug
    call    log_ptr64
    test    eax, eax
    jnz     ws_free_key
    ; After wca success marker
    lea     rcx, msg_debug_after_wca
    call    log_cstrln
    
    ; Debug: accept key computed successfully
    lea     rcx, msg_debug_accept
    call    log_cstrln

    ; Build HTTP request on heap -> [rsp+40h]
    lea     rcx, ws_host
    lea     rdx, ws_path
    mov     r8,  [rsp+50h]       ; keyB64
    lea     r9,  [rsp+40h]
    call    http_ws_request_heap
    test    eax, eax
    jnz     ws_free_accept

    ; Log the request
    lea     rcx, msg_ws_req
    call    log_cstrln
    mov     rcx, [rsp+40h]
    call    log_cstrln

    ; TEMP: skip WS network send/recv and move to cleanup to run HTTP example.com test
    lea     rcx, msg_ws_before_skip
    call    log_cstrln
    jmp     ws_after_net

    ; --- Network send/recv test over plain TCP (port 80) ---
    lea     rcx, msg_ws_net_start
    call    log_cstrln
    ; init winsock
    call    net_init
    ; log init rc
    lea     rcx, msg_ws_init_rc
    call    log_cstrln
    mov     rcx, rax
    call    log_ptr64
    ; connect to ws_host:80
    mov     qword ptr [rsp+58h], 0     ; zero socket storage
    lea     rcx, ws_host
    mov     edx, 80
    lea     r8,  [rsp+58h]         ; &SOCKET storage (reuse local)
    call    net_tcp_connect
    ; log connect rc
    lea     rcx, msg_ws_conn_rc
    call    log_cstrln
    mov     rcx, rax
    call    log_ptr64
    test    eax, eax
    jnz     ws_conn_fail
    lea     rcx, msg_ws_conn_ok
    call    log_cstrln
    ; send request
    ; compute length
    mov     rcx, [rsp+40h]
    call    str_len                ; EAX=len
    ; save len across logging
    mov     dword ptr [rsp+30h], eax
    ; log len
    lea     rcx, msg_req_len
    call    log_cstrln
    mov     eax, dword ptr [rsp+30h]
    mov     rcx, rax
    call    log_ptr64
    ; send(s, req, len)
    mov     rcx, [rsp+58h]         ; SOCKET
    mov     rdx, [rsp+40h]         ; request ptr
    mov     r8d, dword ptr [rsp+30h]   ; length
    call    net_send
    ; log send rc (bytes or -WSAERR)
    lea     rcx, msg_send_rc
    call    log_cstrln
    mov     rcx, rax
    call    log_ptr64
    cmp     eax, 0
    jle     ws_send_fail
    lea     rcx, msg_ws_send_ok
    call    log_cstrln
    ; recv response
    mov     rcx, [g_http_socket]
    lea     rdx, respbuf
    mov     r8d, 2047
    call    net_recv
    cmp     eax, 0
    jle     ws_recv_fail
    lea     rcx, msg_ws_recv_ok
    call    log_cstrln
    ; NUL-terminate and print
    lea     r11, respbuf
    add     r11, rax
    mov     byte ptr [r11], 0
    lea     rcx, msg_ws_resp
    call    log_cstrln
    lea     rcx, respbuf
    call    log_cstrln
    jmp     ws_after_net

ws_conn_fail:
    lea     rcx, msg_ws_conn_fail
    call    log_cstrln
    jmp     ws_after_net

ws_send_fail:
    lea     rcx, msg_ws_send_fail
    call    log_cstrln
    jmp     ws_after_net

ws_recv_fail:
    lea     rcx, msg_ws_recv_fail
    call    log_cstrln

ws_after_net:
    ; close socket if set and cleanup winsock
    lea     rcx, msg_ws_cleanup_enter
    call    log_cstrln
    mov     rcx, [rsp+58h]
    test    rcx, rcx
    jz      ws_after_close
    lea     rdx, msg_ws_cleanup_close
    mov     rcx, rdx
    call    log_cstrln
    call    net_close
ws_after_close:
    call    net_cleanup
    lea     rcx, msg_ws_cleanup_done
    call    log_cstrln

    ; Free request
    lea     rcx, msg_free_req
    call    log_cstrln
    mov     rcx, [rsp+40h]
    call    log_ptr64
    ; TEMP: bypass freeing request to test control flow beyond this point
    ; mov     rcx, [rsp+40h]
    ; call    heap_free
    jmp     ws_free_accept

ws_free_accept:
    ; Free accept
    lea     rcx, msg_free_acc
    call    log_cstrln
    mov     rcx, [rsp+48h]
    call    log_ptr64
    mov     rcx, [rsp+48h]
    test    rcx, rcx
    jz      ws_free_key
    call    heap_free

ws_free_key:
    ; Free key
    lea     rcx, msg_free_key
    call    log_cstrln
    mov     rcx, [rsp+50h]
    call    log_ptr64
    mov     rcx, [rsp+50h]
    test    rcx, rcx
    jz      ws_test_done
    call    heap_free

ws_test_done:
    lea     rcx, msg_reach_http
    call    log_cstrln
    ; --- Plain HTTP GET to example.com:80 to validate networking ---
    lea     rcx, msg_http_test
    call    log_cstrln
    ; init winsock for HTTP test
    lea     rcx, msg_http_init
    call    log_cstrln
    call    net_init
    lea     rcx, msg_http_init_ok
    call    log_cstrln
    ; connect to example.com:80 (use global socket storage to isolate stack issues)
    mov     qword ptr [g_http_socket], 0
    lea     rcx, msg_http_connecting
    call    log_cstrln
    lea     rcx, http_host
    mov     edx, 80
    lea     r8,  g_http_socket
    ; debug: log outSock* address we're passing
    lea     rcx, msg_http_sock
    call    log_cstrln
    lea     rcx, g_http_socket
    call    log_ptr64
    ; log current value at *outSock before call (expect 0)
    mov     rcx, [g_http_socket]
    call    log_ptr64
    ; restore R8 (outSock*) just before the call to avoid clobber from logs
    lea     r8,  g_http_socket
    ; also restore RCX (host) and EDX (port)
    lea     rcx, http_host
    mov     edx, 80
    call    net_tcp_connect
    ; log connect rc (0 = ok, else error)
    lea     rcx, msg_http_conn_rc
    call    log_cstrln
    mov     [rsp+28h], rax           ; save rc
    mov     rcx, [rsp+28h]
    call    log_ptr64
    mov     eax, dword ptr [rsp+28h]
    test    eax, eax
    jnz     http_conn_fail
    lea     rcx, msg_http_conn_ok
    call    log_cstrln
    ; log socket value written by net_tcp_connect (out param)
    lea     rcx, msg_http_sock
    call    log_cstrln
    mov     rcx, [g_http_socket]
    call    log_ptr64
    ; also fetch via getter for comparison (preserve RAX across logging)
    call    net_get_last_socket
    mov     [rsp+28h], rax           ; save return value
    lea     rcx, msg_http_sock
    call    log_cstrln
    mov     rcx, [rsp+28h]
    call    log_ptr64
    ; proceed to send/recv
    ; send request
    lea     rcx, http_req
    call    str_len
    mov     rcx, [g_http_socket]
    lea     rdx, http_req
    mov     r8d, eax
    call    net_send
    mov     [rsp+28h], rax           ; save send rc
    lea     rcx, msg_http_send_rc
    call    log_cstrln
    mov     rcx, [rsp+28h]
    call    log_ptr64
    ; recv response
    mov     rcx, [g_http_socket]
    lea     rdx, respbuf
    mov     r8d, 2047
    call    net_recv
    mov     [rsp+28h], rax           ; save recv rc
    lea     rcx, msg_http_recv_rc
    call    log_cstrln
    mov     rcx, [rsp+28h]
    call    log_ptr64
    mov     eax, dword ptr [rsp+28h]
    cmp     eax, 0
    jle     http_after
    ; NUL-terminate and print response
    lea     r11, respbuf
    add     r11, rax
    mov     byte ptr [r11], 0
    lea     rcx, msg_http_resp
    call    log_cstrln
    lea     rcx, respbuf
    call    log_cstrln
    jmp     http_after

http_conn_fail:
    lea     rcx, msg_http_conn_fail
    call    log_cstrln

http_after:
    ; close and cleanup (no-op if socket invalid); also safe if WSAStartup wasn't called
    mov     rcx, [g_http_socket]
    test    rcx, rcx
    jz      http_after_close
    call    net_close
http_after_close:
    call    net_cleanup

    ; ExitProcess(0)
    xor     ecx, ecx
    call    ExitProcess

    ; never returns
    nop

ws_fail:
    lea     rcx, msg_wsfail
    call    log_cstrln
    ; ExitProcess(error)
    mov     ecx, eax
    call    ExitProcess

main ENDP

END

