; Basic memory helpers and heap wrappers (Windows x64)

OPTION PROLOGUE:none
OPTION EPILOGUE:none

EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC

PUBLIC mem_set
PUBLIC mem_cpy
PUBLIC heap_alloc
PUBLIC heap_free

.code
; void* mem_set(void* dst, int c, size_t n)
; RCX=dst, EDX=c, R8=n
mem_set PROC
    ; Shadow space + align
    sub     rsp, 28h
    mov     rax, rcx          ; rax = dst (return value)
    movzx   edx, dl           ; use only low 8 bits of c
    mov     r9, rcx           ; r9 = cur ptr
    mov     r10, r8           ; r10 = count
    test    r10, r10
    jz      ms_done
ms_loop:
    mov     byte ptr [r9], dl
    inc     r9
    dec     r10
    jnz     ms_loop
ms_done:
    add     rsp, 28h
    ret
mem_set ENDP

; void* mem_cpy(void* dst, const void* src, size_t n)
; RCX=dst, RDX=src, R8=n
mem_cpy PROC
    sub     rsp, 28h
    mov     rax, rcx          ; return dst
    mov     r9, rcx           ; r9 = dst cur
    mov     r10, rdx          ; r10 = src cur
    mov     r11, r8           ; r11 = count
    test    r11, r11
    jz      mc_done
mc_loop:
    mov     al, byte ptr [r10]
    mov     byte ptr [r9], al
    inc     r10
    inc     r9
    dec     r11
    jnz     mc_loop
mc_done:
    add     rsp, 28h
    ret
mem_cpy ENDP

; void* heap_alloc(size_t size)
; R8=not used (Windows x64), RCX=size
heap_alloc PROC
    sub     rsp, 28h
    mov     [rsp+10h], rcx    ; save size local
    call    GetProcessHeap
    mov     rcx, rax          ; RCX = hHeap
    xor     edx, edx          ; RDX = dwFlags = 0
    mov     r8,  [rsp+10h]    ; R8  = size
    call    HeapAlloc
    add     rsp, 28h
    ret
heap_alloc ENDP

; void heap_free(void* p)
; RCX=pointer
heap_free PROC
    sub     rsp, 28h
    mov     [rsp+10h], rcx    ; save pointer
    call    GetProcessHeap
    mov     rcx, rax          ; hHeap
    xor     edx, edx          ; dwFlags=0
    mov     r8,  [rsp+10h]    ; lpMem
    call    HeapFree
    add     rsp, 28h
    ret
heap_free ENDP

END
