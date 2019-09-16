# ptrace 笔记

## ptrace 函数
ptrace系统调从名字上看是用于进程跟踪的，它提供了父进程可以观察和控制其子进程执行的能力，并允许父进程检查和替换子进程的内核镜像(包括寄存器)的值。
### 其基本原理
当使用了ptrace跟踪后，所有发送给被跟踪的子进程的信号(除了SIGKILL)，都会被转发给父进程，而子进程则会被阻塞，这时子进程的状态就会被系统标注为TASK_TRACED。
而父进程收到信号后，就可以对停止下来的子进程进行检查和修改，然后让子进程继续运行。

### 函数原型
```c    
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```
**参数**
- enum __ptrace_request request：指示了ptrace要执行的命令。
- pid_t pid: 指示ptrace要跟踪的进程。
- void *addr: 指示要监控的内存地址。
- void *data: 存放读取出的或者要写入的数据。

操作命令request包括：
  /* Indicate that the process making this request should be traced.
     All signals received by this process can be intercepted by its
     parent, and its parent can use the other `ptrace' requests.  */
PTRACE_TRACEME = 0,

  /* Return the word in the process's text space at address ADDR.  */
PTRACE_PEEKTEXT = 1,

  /* Return the word in the process's data space at address ADDR.  */
  PTRACE_PEEKDATA = 2,

  /* Return the word in the process's user area at offset ADDR.  */
  PTRACE_PEEKUSER = 3,

  /* Write the word DATA into the process's text space at address ADDR.  */
  PTRACE_POKETEXT = 4,

  /* Write the word DATA into the process's data space at address ADDR.  */
  PTRACE_POKEDATA = 5,

  /* Write the word DATA into the process's user area at offset ADDR.  */
  PTRACE_POKEUSER = 6,

  /* Continue the process.  */
  PTRACE_CONT = 7,

  /* Kill the process.  */
  PTRACE_KILL = 8,

  /* Single step the process.
     This is not supported on all machines.  */
  PTRACE_SINGLESTEP = 9,

  /* Get all general purpose registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_GETREGS = 12,

  /* Set all general purpose registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_SETREGS = 13,

  /* Get all floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_GETFPREGS = 14,

  /* Set all floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_SETFPREGS = 15,

  /* Attach to a process that is already running. */
  PTRACE_ATTACH = 16,

  /* Detach from a process attached to with PTRACE_ATTACH.  */
  PTRACE_DETACH = 17,

  /* Get all extended floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_GETFPXREGS = 18,

  /* Set all extended floating point registers used by a processes.
     This is not supported on all machines.  */
   PTRACE_SETFPXREGS = 19,

  /* Continue and stop at the next (return from) syscall.  */
  PTRACE_SYSCALL = 24,

  /* Set ptrace filter options.  */
  PTRACE_SETOPTIONS = 0x4200,

  /* Get last ptrace message.  */
  PTRACE_GETEVENTMSG = 0x4201,

  /* Get siginfo for process.  */
  PTRACE_GETSIGINFO = 0x4202,

  /* Set new siginfo for process.  */
  PTRACE_SETSIGINFO = 0x4203,

  /* Get register content.  */
  PTRACE_GETREGSET = 0x4204,

  /* Set register content.  */
  PTRACE_SETREGSET = 0x4205,

  /* Like PTRACE_ATTACH, but do not force tracee to trap and do not affect
     signal or group stop state.  */
  PTRACE_SEIZE = 0x4206,

  /* Trap seized tracee.  */
  PTRACE_INTERRUPT = 0x4207,

  /* Wait for next group event.  */
  PTRACE_LISTEN = 0x4208,

  PTRACE_PEEKSIGINFO = 0x4209,

  PTRACE_GETSIGMASK = 0x420a,

  PTRACE_SETSIGMASK = 0x420b,

  PTRACE_SECCOMP_GET_FILTER = 0x420c


> https://www.cnblogs.com/tangr206/articles/3094358.html