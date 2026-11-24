#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Section {
    std::string name;
    uint32_t va, vsize, raw, rawsize;
    bool exec;
};

struct PeImage {
    std::vector<uint8_t> data;
    uint64_t image_base = 0;
    uint32_t entry_rva = 0;
    std::vector<Section> sections;
    std::vector<std::pair<uint64_t, uint32_t>> functions;  // va, size
    const Section* byRva(uint32_t rva) const;
};

bool loadPe(const char* path, PeImage& out, std::string* err);

struct LiftResult {
    bool ok = false;
    std::string code;
    std::vector<std::string> unsupported;
    int insnCount = 0;
    bool usesRipData = false;
    bool hasCall = false;
    bool usesMemory = false;   // 任何内存操作数
    bool writesMemory = false; // 写内存

};

// 把某个函数转译成 C++（方案书阶段 3 的单函数形态）
LiftResult liftFunction(const PeImage& pe, uint64_t va, uint32_t size);

// 找「纯算法」候选函数：无 call、无 RIP 相对数据引用、全部指令都支持
bool pickPureFunction(const PeImage& pe, size_t minSize, size_t maxSize,
                      std::vector<std::pair<uint64_t, uint32_t>>& out);
