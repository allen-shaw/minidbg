#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <fstream>
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
    // 如果在调用waitpid()函数时，当指定等待的子进程已经停止运行或结 束了，则waitpid()会立即返回；
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
        // 0x<hexadecimal> -> 地址断点
        // <line>:<filename> -> 行号断点
        // <anything else> ->函数名断点
        if (args[1][0] == '0' && args[1][1] == 'x') 
        {
            std::string addr{args[1], 2}; //粗暴认定用户在地址前加了"0x"
            set_breakpoint_at(std::stol(addr, 0, 16));
        }
        else if (args[1].find(':') != std::string::npos)
        {
            auto file_and_line = utils::split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        } 
        else
        {
            set_breakpoint_at_function(args[1]);
        }
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
    else if (utils::is_prefix(command, "stepi"))
    {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_srouce(line_entry->file->path, line_entry->line);
    }
    else if (utils::is_prefix(command, "step"))
    {
        step_in();
    }
    else if (utils::is_prefix(command, "next"))
    {
        step_over();
    }
    else if (utils::is_prefix(command, "finish"))
    {
        step_out();
    }
    else if (utils::is_prefix(command, "symbol"))
    {
        auto symbols = lookup_symbol(args[1]);
        for (auto &&s : symbols)
        {
            char *str;
            sprintf(str, "%s %s 0x%04x", s.name, Symbol::to_string(s.type), s.addr);
            std::cout << str << std::endl;
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
    // 我们在收到SIGTRAP的时候修正PC指针的值，因此这里无需再做一次修正
    std::intptr_t possible_breakpoint_location = get_pc();

    if (m_breakpoints.count(possible_breakpoint_location))
    {
        // 所在位置有断点
        auto it = m_breakpoints.find(possible_breakpoint_location);
        if (it != m_breakpoints.end())
        {
            auto &bp = it->second;

            if (bp.is_enabled())
            {
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

    auto siginfo = get_signal_info();

    switch (siginfo.si_signo)
    {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "Yay, segmentfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
        break;
    }
}

// TODO 处理成员函数或内联
dwarf::die Debugger::get_function_from_pc(uint64_t pc)
{
    // 遍历所有compilation_units
    for (auto &cu : m_dwarf.compilation_units())
    {
        // 当前编译单元是否含有对应的地址
        if (die_pc_range(cu.root()).contains(pc))
        {
            // 遍历该cu下的每一个die
            for (const auto &die : cu.root())
            {
                // die类型必须是一个函数
                if (die.tag == dwarf::DW_TAG::subprogram)
                {
                    // pc在当前函数则返回
                    if (die_pc_range(die).contains(pc))
                    {
                        return die;
                    }
                }
            }
        }
    }

    throw std::out_of_range("Cannot find function");
}

dwarf::line_table::iterator
Debugger::get_line_entry_from_pc(uint64_t pc)
{
    // 遍历所有compilation_units
    for (auto &cu : m_dwarf.compilation_units())
    {
        if (die_pc_range(cu.root()).contains(pc))
        {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it != lt.end())
            {
                return it;
            }

            throw std::out_of_range("Cannot find line entry");
        }
    }

    throw std::out_of_range("Cannot find line entry");
}

/**
 * file_name: 源文件名
 * line:      关注的行号，文件第几行      
 * n_lines_context: 关注行所在的上下文，要打印前n行和后n行
 */
void Debugger::print_srouce(const std::string &file_name, unsigned int line, unsigned int n_lines_context)
{
    std::ifstream file(file_name);

    /**
     * 在当前行附近设置一个窗口
     * start_line: 要打印的起始行
     * end_line:    要打印的结束行
     */
    unsigned int start_line;
    unsigned int end_line;

    if (line <= n_lines_context)
    {
        // 关注行比上下文范围小，就是从第一行开始打印
        start_line = 1;
    }
    else
    {
        // 开始行就是关注行行号前n行
        start_line = line - n_lines_context;
    }

    if (line < n_lines_context)
    {
        end_line = line + n_lines_context + (n_lines_context - line) + 1;
    }
    else
    {
        // 结束行就是关注行行号后n行
        end_line = line + n_lines_context + 1;
    }

    char c;
    unsigned int current_line = 1u; // 当前行

    // 读取文件到开始行数
    while (current_line != start_line && file.get(c)) // TODO 为什么不换成getline，不用每次都读写一个字符
    {
        if (c == '\n')
        {
            // 读完一行
            current_line++;
        }
    }

    //如果我们在当前行则输出光标
    std::cout << (current_line == line ? "> " : "  ");

    // 输出start_line 到 end_line 之前的代码
    while (current_line <= end_line && file.get(c))
    {
        std::cout << c;
        if (c == '\n')
        {
            ++current_line;
            // 每一行都判断是否是关注的行号，如果是，则输出>
            std::cout << (current_line == line ? ">" : "  ");
        }
    }

    // 最后输出endl来flushed
    std::cout << std::endl;
}

siginfo_t Debugger::get_signal_info()
{
    siginfo_t info;

    // 获取关于子进程发送的最后一个信号的信息。
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void Debugger::handle_sigtrap(siginfo_t info)
{
    switch (info.si_code)
    {
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        // 触发断点
        set_pc(get_pc() - 1); // TODO: 为什么要回到上一条指令？
        std::cout << "Hit breakpoint at address 0x" << get_pc() << std::endl;

        // 获取当前行
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_srouce(line_entry->file->path, line_entry->line);
        return;
    }
    break;
    case TRAP_TRACE:
        // 单步执行
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void Debugger::single_step_instruction()
{
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::single_step_instruction_with_breakpoint_check()
{
    if (m_breakpoints.count(get_pc()))
    {
        // 当前指令有断点
        step_over_breakpoint();
    }
    else
    {
        single_step_instruction();
    }
}

void Debugger::remove_breakpoint(std::intptr_t addr)
{
    if (m_breakpoints.at(addr).is_enabled())
    {
        m_breakpoints.at(addr).disable();
    }

    m_breakpoints.erase(addr);
}

void Debugger::step_in()
{
    auto line = get_line_entry_from_pc(get_pc())->line;

    // 执行到下一步
    while (get_line_entry_from_pc(get_pc())->line == line)
    {
        single_step_instruction_with_breakpoint_check();
    }

    // 打印当前行
    auto line_entry = get_line_entry_from_pc(get_pc());
    print_srouce(line_entry->file->path, line_entry->line);
}

// 解决方法是在源码的下一行设置断点
// 可能不是连续的下一行，因为我们可能在一个循环中或在某些条件结构中。
// TODO 真正的那些调试器通常会检查目前正在执行的是什么指令，然后计算出所有可能的分支目标，然后在所有可能上设置断点。
// 采用简单做法，在当前函数的所有行上设置断点
void Debugger::step_over()
{
    auto func = get_function_from_pc(get_pc());

    // 函数入口地址，返回地址
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);

    auto line = get_line_entry_from_pc(func_entry);
    auto current_line = get_line_entry_from_pc(get_pc());

    std::vector<std::intptr_t> to_delete;

    // 从函数入口开始，给每一行（除了当前行）打断点
    while (line->address < func_end)
    {
        // 如果不是当前行而且没有断点，则添加一个断点
        if (line->address != current_line->address && m_breakpoints.count(line->address))
        {
            set_breakpoint_at(line->address);
            to_delete.push_back(line->address);
        }
        ++line;
    }

    // 在返回地址也打断点
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    if (!m_breakpoints.count(return_address))
    {
        set_breakpoint_at(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    // 移除断点
    for (auto& addr: to_delete)
    {
        remove_breakpoint(addr);
    }
}

// 在函数return的地方设置断点并continue
void Debugger::step_out()
{
    // 每个栈帧对应一个函数
    // %rbp指向栈帧开始，%rsp指向栈顶。
    auto frame_pointer = get_register_value(m_pid, reg::rbp);

    //  返回地址保存在栈帧开始的后8字节中
    auto return_address = read_memory(frame_pointer + 8);

    bool should_remove_breakpoint = false;
    if (!m_breakpoints.count(return_address))
    {
        // 如果return处没有断点，则添加一个
        set_breakpoint_at(return_address);
        should_remove_breakpoint = true;
    }

    // 继续执行到断点处
    continue_execution();

    // 移除掉返回地址上的断点
    if (should_remove_breakpoint)
    {
        remove_breakpoint(return_address);
    }
}

void Debugger::set_breakpoint_at_function(const std::string &func_name)
{
    for (const auto &cu : m_dwarf.compilation_units())
    {
        for (const auto &die : cu.root()) 
        {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == func_name)
            {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);

                // 一个函数的DW_AT_low_pc实际上并不指向用户代码的起始地址，而是指向函数的序言
                // 编译器通常会为函数生成序言和结尾（prologue and epilogue）来保存和恢复寄存器，操作栈指针等。
                // 这对我们来说并不是十分有用，因此我们递增入口的行号来到用户代码的第一行而不是函数序言。
                ++entry;

                set_breakpoint_at(entry->address);
            }
        }
    }
}

void Debugger::set_breakpoint_at_source_line(const std::string &file, unsigned int line)
{
    for (const auto &cu : m_dwarf.compilation_units())
    {
        if (utils::is_suffix(file, at_name(cu.root())))
        {
            const auto &linetable = cu.get_line_table();
            for (const auto &entry : linetable)
            {
                //  is_stmt检查行表入口是否被标记为一个语句的开头,
                // 这是由编译器根据它认为是断点的最佳目标的地址设置的。
                if (entry.is_stmt && entry.line == line) 
                {
                    set_breakpoint_at(entry.address);
                    return;
                }
            }
        }
    }
}

std::vector<Symbol> Debugger::lookup_symbol(const std::string &name)
{
    std::vector<Symbol> symbols;

    for (auto &sec : m_elf.sections())
    {
        if (sec.get_hdr().type != elf::sht::symtab &&
            sec.get_hdr().type != elf::sht::dynsym)
        {
            continue;
        }

        for (auto sym: sec.as_symtab()) 
        {
            if (sym.get_name() == name) 
            {
                auto &data = sym.get_data();
                symbols.push_back(Symbol{Symbol::to_symbol_type(data.type()), sym.get_name(), data.value});
            }
        }
    }

    return symbols;
}
