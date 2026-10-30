# Fixed-command setuid helper: invoke only BusyBox ping, with an empty environment.
.section .text
.global _start
_start:
    mov %esp, %esi
    mov $23, %eax
    xor %ebx, %ebx
    int $0x80
    test %eax, %eax
    js failed
    mov (%esi), %ecx
    add $2, %ecx
    shl $2, %ecx
    sub %ecx, %esp
    movl $busybox, (%esp)
    movl $ping, 4(%esp)
    mov $1, %ecx
copy_args:
    cmp (%esi), %ecx
    jge execute
    mov 4(%esi,%ecx,4), %eax
    mov %eax, 4(%esp,%ecx,4)
    inc %ecx
    jmp copy_args
execute:
    movl $0, 4(%esp,%ecx,4)
    mov $11, %eax
    mov $busybox, %ebx
    mov %esp, %ecx
    mov $empty_env, %edx
    int $0x80
failed:
    mov $1, %eax
    mov $1, %ebx
    int $0x80
.section .rodata
busybox: .asciz "/bin/busybox"
ping: .asciz "ping"
.align 4
empty_env: .long 0
.section .note.GNU-stack,"",@progbits
