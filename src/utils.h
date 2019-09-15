#pragma once

#include <string>
#include <vector>

namespace utils
{
std::vector<std::string> split(const std::string& s, char delimiter); 

bool is_prefix(const std::string& s, const std::string& of);
}
