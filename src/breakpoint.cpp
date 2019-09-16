#include <iostream>
#include <string>
#include <sys/ptrace.h>
#include "breakpoint.h"

using namespace minidbg;

const uint64_t INT3 = 0xcc;

void BreakPoint::enable() 
{
    std::cout << "BreakPoint::enable" << std::endl;

    // 读取m_addr 上的数据
    long int data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    m_saved_data = static_cast<uint8_t>(data & 0xff);       // 保存最低一个字节

    uint64_t data_with_int3 = ((data & ~0xff) | INT3);      // 将最低一个字节改为0xcc，得到中断指令

    // 将中断指令写入到断点地址
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

    m_enabled = true;
}

void BreakPoint::disable() 
{
    std::cout << "BreakPoint::disable" << std::endl;

    // 读取断点地址处的指令
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);

    // 去掉中断指令后，添加回原来的指令
    uint64_t restored_data = ((data & ~0xff) | m_saved_data);

    // 写回原来的指令
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

    m_enabled = false;
}