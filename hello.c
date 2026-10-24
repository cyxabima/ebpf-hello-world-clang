#include <bpf/libbpf.h>
#include <stdio.h>
#include <signal.h>
#include <unistdio.h>


int main(){

  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;

  obj = bpf_object__open_file("hello.bpf.o", NULL);

  if(!obj){
    fprintf(stderr, "Failed to open file");
    return 1;
  }

  if(bpf_object__load(obj)){
    fprintf(stderr, "failed to load bpf object");
    return 1;
  }

  prog = bpf_object__find_program_by_name(obj, "hello");

if (!prog) {
        fprintf(stderr, "Failed to find BPF program 'hello'\n");
        bpf_object__close(obj);
        return 1;
  }

  link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_exexcve");

  if(!link){
        fprintf(stderr, "Failed to link to trace point\n");
        bpf_object__close(obj);
        return 1;
    }

   printf("Attached. Run a command .\n");


  return 0;
}
