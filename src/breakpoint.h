#pragma once
#include <cstdint>
#include <sys/ptrace.h>

namespace minidbg 
{
class BreakPoint 
{
public:
    BreakPoint(pid_t pid, std::intptr_t addr)
        :m_pid(pid),m_addr(addr),m_enabled(false),m_saved_data(0)
    {}

    void enable();
    void disable();

    inline 
    bool is_enabled() const {
        return m_enabled;
    }

    inline
    uint8_t get_address() const {
        return m_addr;
    }


private:
    pid_t           m_pid;
    std::intptr_t   m_addr;
    bool            m_enabled;
    uint8_t         m_saved_data;       // 保存断点的地址
};
}
