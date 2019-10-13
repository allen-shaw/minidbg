#pragma once

#include <string>
#include "elf/elf++.hh"

enum class symbol_type
{
    notype,  // 无类型
    object,  // 数据对象
    func,    // 函数对象
    section, // 和section相关联的符号
    file     // 和对象文件相联系的源码文件
};

struct Symbol
{
    symbol_type     type;
    std::string     name;
    std::uintptr_t  addr;

    static std::string to_string(symbol_type st);   

    static symbol_type to_symbol_type(elf::stt sym); 
};