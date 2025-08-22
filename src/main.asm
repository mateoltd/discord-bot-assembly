; Minimal MASM x64 entry point to verify toolchain

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN ExitProcess:PROC
EXTERN log_cstrln:PROC
EXTERN net_init:PROC
EXTERN net_cleanup:PROC

.data
msg_boot    db "Discord ASM bot bootstrap OK", 0
msg_wsok    db "Winsock init OK", 0
msg_wsfail  db "Winsock init FAILED", 0

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

