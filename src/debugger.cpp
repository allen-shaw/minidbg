#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "linenoise.h"
#include "debugger.h"
#include "utils.h"

using namespace minidbg;

void Debugger::run() 
{
    std::cout << "Debugger Run() " << m_prog_name << " " <<  m_pid << std::endl;

    int wait_status;
    auto options = 0;

    // 当被调试进程启动完成，他将会发送SIGTRAP 信号，
    // 表示这是一个跟踪或是遇到断点。我们通过watpid函数来等待直到收到这个信号
    // 如果在调用waitpid()函数时，当指定等待的子进程已经停止运行或结束了，则waitpid()会立即返回；
    // 但是如果子进程还没有停止运行或结束，则调用waitpid()函数的父进程则会被阻塞，暂停运行。
    waitpid(m_pid, &wait_status, options);

    std::cout << "wait status " << wait_status << std::endl; 

    char *line = nullptr;

    // 当我们知道这个进程准备好被调试后，我们监听用户的输入，linenoise 函数会自己显示一个提示符并处理用户的输入
    while ((line = linenoise("minidbg> ")) != nullptr) 
    {
        // 当我们获取到用户输入后，我们把命令发送到相应的处理函数中，
        // 然后我们将这个命令添加到 linenoise 历史并释放资源。
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void Debugger::handle_command(const std::string& line)
{
    std::cout << "handle_command " << line << std::endl;
    
    std::vector<std::string> args = utils::split(line, ' ');
    auto command = args[0];

    if (utils::is_prefix(command, "continue")) 
    {
        continue_execution();
    }
    else
    {
        std::cerr << "Unknown command" << std::endl;
    }
}

void Debugger::continue_execution() 
{
    std::cout << "continue_execution" << std::endl;

    // continue_execution 函数将使用ptrace来告知被调试进程继续执行
    // 然后用waitpid函数直到它收到信号。
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}