#pragma once

#include <string>
#include <unordered_map>
#include <iostream>
#include <linux/types.h>

#include "breakpoint.h"
#include "registers.h"

namespace minidbg
{
class Debugger
{
public:
    Debugger(std::string prog_name, pid_t pid) 
        : m_prog_name(std::move(prog_name)), m_pid(pid) {}

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

private:
    std::string m_prog_name;
    pid_t m_pid;

    std::unordered_map<std::intptr_t, BreakPoint> m_breakpoints;
};
} // namespace minidbg