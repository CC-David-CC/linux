.section .text
.global _start
_start:
    mov $46, %eax              # setgid(1000)
    mov $1000, %ebx
    int $0x80
    test %eax, %eax
    js failed

    mov $23, %eax              # setuid(1000)
    mov $1000, %ebx
    int $0x80
    test %eax, %eax
    js failed

    mov $11, %eax              # execve("/bin/setsid", argv, envp)
    mov $shell_path, %ebx
    mov $shell_argv, %ecx
    mov $shell_env, %edx
    int $0x80

failed:
    mov $1, %eax
    mov $1, %ebx
    int $0x80

.section .rodata
shell_path: .asciz "/sbin/terminal-mux"
shell_arg:  .asciz "setsid"
ctty_arg: .asciz "/bin/cttyhack"
sh_arg: .asciz "/bin/sh"
interactive: .asciz "-i"
home_env: .asciz "HOME=/home/guest"
path_env: .asciz "PATH=/bin:/sbin:/usr/bin"
term_env: .asciz "TERM=vt100"
.align 4
shell_argv: .long shell_path, 0
shell_env: .long home_env, path_env, term_env, 0

.section .note.GNU-stack,"",@progbits
