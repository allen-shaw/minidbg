#pragma once

#include <string>
#include <unordered_map>
#include <iostream>
#include <linux/types.h>
#include <fcntl.h>
#include <signal.h>

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

#include "breakpoint.h"
#include "registers.h"

namespace minidbg
{
class Debugger
{
public:
    Debugger(std::string prog_name, pid_t pid)
        : m_prog_name(std::move(prog_name)), m_pid(pid)
    {
        // 使用open而不是std::ifstream的原因是ELF loader 需要给mmap传递一个UNIX文件描述符，从而它能把文件映射到内存而不是每次读取一点点。
        auto fd = open(m_prog_name.c_str(), O_RDONLY);

        m_elf = elf::elf(elf::create_mmap_loader(fd));
        m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
    }

    void run();

private:
    void handle_command(const std::string &line);

    void continue_execution();

    void set_breakpoint_at(std::intptr_t addr);

    uint64_t read_memory(std::intptr_t addr);

    void write_memory(std::intptr_t addr, uint64_t value);

    uint64_t get_pc();

    void set_pc(uint64_t pc);

    void step_over_breakpoint();

    void wait_for_signal();

    dwarf::die get_function_from_pc(uint64_t pc);

    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);

    void print_srouce(const std::string &file_name, unsigned int line, unsigned int n_lines_context = 5);   

    siginfo_t get_signal_info();

    void handle_sigtrap(siginfo_t info);

    void single_step_instruction();

    void single_step_instruction_with_breakpoint_check();

    void remove_breakpoint(std::intptr_t addr);   

    void step_in();

    void step_over();

    void step_out();

private:
    std::string m_prog_name;
    pid_t m_pid;

    std::unordered_map<std::intptr_t, BreakPoint> m_breakpoints;

    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
};
} // namespace minidbg