#pragma once

#include <string>
#include <unordered_map>
#include <iostream>
#include <linux/types.h>

#include "breakpoint.h"

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

private:
    std::string m_prog_name;
    pid_t m_pid;

    std::unordered_map<std::intptr_t, BreakPoint> m_breakpoints;
};
} // namespace minidbg