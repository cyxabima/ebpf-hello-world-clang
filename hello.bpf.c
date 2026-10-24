#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


SEC("tracepoint/syscalls:sys_enter_execve")
int hello(void *ctx){ // ctx of void pointer as i am not using any 

  bpf_printk("hello World");
  return 0;
}

char __lisence[]  SEC("license")="GPL";
