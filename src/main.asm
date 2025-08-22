; Minimal MASM x64 entry point to verify toolchain

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN ExitProcess:PROC
EXTERN log_cstrln:PROC
EXTERN net_init:PROC
EXTERN net_cleanup:PROC
EXTERN config_load_token_heap:PROC
EXTERN heap_free:PROC
EXTERN net_tcp_connect:PROC
EXTERN net_close:PROC

.data
msg_boot    db "Discord ASM bot bootstrap OK", 0
msg_wsok    db "Winsock init OK", 0
msg_wsfail  db "Winsock init FAILED", 0
msg_cfg_ok  db "Config: DISCORD_BOT_TOKEN loaded", 0
msg_cfg_nf  db "Config: DISCORD_BOT_TOKEN not found", 0
host_discord db "discord.com", 0
msg_tcp_ok  db "TCP connect to discord.com:443 OK", 0
msg_tcp_fail db "TCP connect to discord.com:443 FAILED", 0

.code
main PROC
    ; Reserve shadow space (32 bytes) + 8 for alignment (total 0x28)
    sub     rsp, 28h

    ; log_cstrln("Discord ASM bot bootstrap OK")
    lea     rcx, msg_boot
    call    log_cstrln

    ; Initialize Winsock
    call    net_init            ; EAX = 0 on success
    test    eax, eax
    jnz     ws_fail

    ; Success
    lea     rcx, msg_wsok
    call    log_cstrln

    ; Load bot token via config (env -> DISCORD_TOKEN_FILE -> config/token.txt)
    lea     rcx, [rsp+20h]         ; &outStr temp storage
    call    config_load_token_heap
    test    eax, eax
    jnz     no_token
    ; success -> log and free
    lea     rcx, msg_cfg_ok
    call    log_cstrln
    mov     rcx, [rsp+20h]
    call    heap_free
    jmp     after_cfg

no_token:
    lea     rcx, msg_cfg_nf
    call    log_cstrln

after_cfg:
    ; Quick TCP connect test to discord.com:443 (no TLS yet)
    lea     rcx, host_discord      ; host
    mov     edx, 443               ; port
    lea     r8,  [rsp+18h]         ; &SOCKET storage
    call    net_tcp_connect
    test    eax, eax
    jnz     tcp_fail
    ; success -> log and close
    lea     rcx, msg_tcp_ok
    call    log_cstrln
    mov     rcx, [rsp+18h]
    call    net_close
    jmp     after_tcp

tcp_fail:
    lea     rcx, msg_tcp_fail
    call    log_cstrln

after_tcp:
    ; Cleanup and exit 0
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

