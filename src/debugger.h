#pragma once

#include <string>
#include <iostream>
#include <linux/types.h>

namespace minidbg 
{
class Debugger 
{
public:

    Debugger(std::string prog_name, pid_t pid):
        m_prog_name(std::move(prog_name)), m_pid(pid) {}

    void run();

private:

    void handle_command(const std::string& line);

    void continue_execution();

private:

    std::string     m_prog_name;
    pid_t           m_pid;
};
}