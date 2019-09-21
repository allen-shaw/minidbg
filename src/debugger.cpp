#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include "linenoise.h"
#include "debugger.h"
#include "utils.h"

using namespace minidbg;

void Debugger::run()
{
    std::cout << "Debugger Run() " << m_prog_name << " " << m_pid << std::endl;

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

void Debugger::handle_command(const std::string &line)
{
    std::cout << "handle_command " << line << std::endl;

    std::vector<std::string> args = utils::split(line, ' ');
    auto command = args[0];

    if (utils::is_prefix(command, "continue"))
    {
        continue_execution();
    }
    else if (utils::is_prefix(command, "break"))
    {
        std::string addr{args[1], 2}; //粗暴认定用户在地址前加了"0x"
        set_breakpoint_at(std::stol(addr, 0, 16));
    }
    else if (utils::is_prefix(command, "register"))
    {
        if (utils::is_prefix(args[1], "dump"))
        {
            dump_registers(m_pid);
        }
        else if (utils::is_prefix(args[1], "read"))
        {
            auto reg = get_register_from_name(args[2]);
            std::cout << get_register_value(m_pid, reg) << std::endl;
        }
        else if (utils::is_prefix(args[1], "write"))
        {
            // 假设用户输入0xVal,去掉0x
            std::string val{args[3], 2};
            auto reg = get_register_from_name(args[2]);
            set_register_value(m_pid, reg, std::stol(val, 0, 16)); // 输入格式为16进制
        }
    }
    else if (utils::is_prefix(command, "memory"))
    {
        std::string addr{args[2], 2};

        if (utils::is_prefix(args[1], "read"))
        {
            std::cout << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        else if (utils::is_prefix(args[1], "write"))
        {
            std::string val{args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else
    {
        std::cerr << "Unknown command" << std::endl;
    }
}

void Debugger::continue_execution()
{
    std::cout << "continue_execution" << std::endl;

    // TODO 为什么需要加step_over_breakpoint();
    step_over_breakpoint();
    
    // continue_execution 函数将使用ptrace来告知被调试进程继续执行
    // 然后用waitpid函数直到它收到信号。
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    wait_for_signal();
}

void Debugger::set_breakpoint_at(std::intptr_t addr)
{
    std::cout << "set_breakpoint_at address 0x" << std::hex << addr << std::endl;

    BreakPoint bp(m_pid, addr);
    bp.enable();

    m_breakpoints.insert({addr, bp});
}

uint64_t Debugger::read_memory(std::intptr_t addr)
{
    return ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr);
}

void Debugger::write_memory(std::intptr_t addr, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, m_pid, addr, value);
}

// TODO 一次读写多个字节，可以使用process_vm_readv 和 process_vm_writev 或 /proc/<pid>/mem 来代替 ptrace。

uint64_t Debugger::get_pc()
{
    return get_register_value(m_pid, reg::rip);
}

void Debugger::set_pc(uint64_t pc)
{
    set_register_value(m_pid, reg::rip, pc);
}

void Debugger::step_over_breakpoint()
{
    // TODO 为什么要-1
    std::intptr_t possible_breakpoint_location = get_pc() - 1;

    if (m_breakpoints.count(possible_breakpoint_location))
    {
        // 所在位置有断点
        auto it = m_breakpoints.find(possible_breakpoint_location);
        if (it != m_breakpoints.end())
        {
            auto &bp = it->second;

            if (bp.is_enabled())
            {
                auto previous_instruction_address = possible_breakpoint_location;
                set_pc(previous_instruction_address);

                bp.disable();
                ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);

                wait_for_signal();
                bp.enable();
            }
        }
    }
}

void Debugger::wait_for_signal() 
{
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}