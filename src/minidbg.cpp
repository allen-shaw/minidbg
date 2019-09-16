#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <string>
#include "debugger.h"

void log(const std::string& msg) 
{
    std::cout << msg << std::endl;
}

void error(const std::string& msg) 
{
    std::cerr << msg << std::endl;
}

int main(int argc, char *argv[]) 
{
    if (argc < 2) 
    {
        error("Program name not specified");
        return -1;
    }

    char *prog = argv[1];
    log(prog);

    auto pid = fork();
    if (pid == 0) 
    {
        // 子进程，启动被调试的程序
        log("sub process");
        std::cout << pid << std::endl;

        // ptrace系统调从名字上看是用于进程跟踪的，
        // 它提供了父进程可以观察和控制其子进程执行的能力，
        // 并允许父进程检查和替换子进程的内核镜像(包括寄存器)的值。
        // 其基本原理是: 当使用了ptrace跟踪后，所有发送给被跟踪的子进程的信号(除了SIGKILL)，
        // 都会被转发给父进程，而子进程则会被阻塞，
        // 这时子进程的状态就会被系统标注为TASK_TRACED。
        // 而父进程收到信号后，就可以对停止下来的子进程进行检查和修改，然后让子进程继续运行。  
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);
    }
    else if (pid >= 1)
    {
        // 父进程，执行调试器
        log("parent process");
        std::cout << "SubProcess Id" << pid << std::endl;

        minidbg::Debugger dbg(prog, pid);
        dbg.run();
    }
    else 
    {
        std::cerr << "fork fail!" << std::endl;
    }
}