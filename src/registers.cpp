#include <iostream>
#include <sys/ptrace.h>
#include <algorithm>
#include <iomanip>
#include "registers.h"

reg_value_t *minidbg::get_reg_value(user_regs_struct &regs, reg r)
{
    switch (r)
    {
    case reg::rax:
        return &regs.rax;
        break;
    case reg::rbx:
        return &regs.rbx;
        break;
    case reg::rcx:
        return &regs.rcx;
        break;
    case reg::rdx:
        return &regs.rdx;
        break;
    case reg::rdi:
        return &regs.rdi;
        break;
    case reg::rsi:
        return &regs.rsi;
        break;
    case reg::rbp:
        return &regs.rbp;
        break;
    case reg::rsp:
        return &regs.rsp;
        break;
    case reg::r8:
        return &regs.r8;
        break;
    case reg::r9:
        return &regs.r9;
        break;
    case reg::r10:
        return &regs.r10;
        break;
    case reg::r11:
        return &regs.r11;
        break;
    case reg::r12:
        return &regs.r12;
        break;
    case reg::r13:
        return &regs.r13;
        break;
    case reg::r14:
        return &regs.r14;
        break;
    case reg::r15:
        return &regs.r15;
        break;
    case reg::rip:
        return &regs.rip;
        break;
    case reg::eflags:
        return &regs.eflags;
        break;
    case reg::cs:
        return &regs.cs;
        break;
    case reg::orig_rax:
        return &regs.orig_rax;
        break;
    case reg::fs_base:
        return &regs.fs_base;
        break;
    case reg::gs_base:
        return &regs.gs_base;
        break;
    case reg::fs:
        return &regs.fs;
        break;
    case reg::gs:
        return &regs.gs;
        break;
    case reg::ss:
        return &regs.ss;
        break;
    case reg::ds:
        return &regs.ds;
        break;
    case reg::es:
        return &regs.es;
        break;
    default:
        std::cerr << "Unknown Register" << std::endl;
        return nullptr;
        break;
    }
}

reg_value_t minidbg::get_register_value(pid_t pid, reg r)
{
    user_regs_struct regs;

    // 获取当前所有寄存器数据
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    return *get_reg_value(regs, r);
}

void minidbg::set_register_value(pid_t pid, reg r, reg_value_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    reg_value_t *reg_value = get_reg_value(regs, r);
    *reg_value = value;

    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

reg_value_t minidbg::get_register_value_from_dwarf_register(pid_t pid, int regnum)
{
    std::cout << "get_register_value_from_dwarf_register " << pid << " regnum " << regnum << std::endl;

    // 判断regnum 是否在g_register_descriptors 中
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [regnum](auto &rd) { return rd.dwarf_r == regnum; });

    if (it == end(g_register_descriptors))
    {
        throw std::out_of_range("Unknown dwarf register");
    }

    return get_register_value(pid, it->r);
}

std::string minidbg::get_register_name(reg r)
{
    std::cout << "get_register_name " << int(r) << std::endl;

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto &rd) { return rd.r == r; });

    if (it == end(g_register_descriptors))
    {
        throw std::out_of_range("Unknown dwarf register");
    }

    return it->name;
}

minidbg::reg minidbg::get_register_from_name(const std::string &name)
{
    std::cout << "get_register_from_name " << name << std::endl;

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [name](auto &rd) { return rd.name == name; });

    if (it == end(g_register_descriptors))
    {
        throw std::out_of_range("Unknown dwarf register");
    }

    return it->r;
}

void minidbg::dump_registers(pid_t pid)
{
    for (const auto &rd : g_register_descriptors)
    {
        // 16进制输出寄存器的值 0x00000000000234
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex << get_register_value(pid, rd.r) << std::endl;
    }
}