#pragma once
// 桌面 GLSL → GLES 3.00 自动改写（阶段 6 用；纯字符串处理，可在 Linux CI 上验证）
#include <string>

// is_fragment=true 时补 precision 声明、把 gl_FragColor 改成自定义 out 变量。
// 返回改写后的源码；同名输入输出稳定（可做哈希缓存）。
std::string rewrite_glsl_to_es3(const std::string& src, bool is_fragment);

// 调试用：改写前后都落盘，文件名带哈希前缀
std::string glsl_hash8(const std::string& src);
