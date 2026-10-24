#include <bpf/libbpf.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>


static volatile sig_atomic_t existing;

static void handle_signal(int sig){
  existing = 1;
}

int main(){

  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;


  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

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

  link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");

  if(!link){
        fprintf(stderr, "Failed to link to trace point\n");
        bpf_object__close(obj);
        return 1;
    }


  while (!existing) {
   pause();
  }

   printf("Attached. Run a command \n");


    bpf_link__destroy(link);
    bpf_object__close(obj);

  return 0;
}
