#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>

struct Section {
    std::string name;
    uint32_t va, vsize, raw, rawsize;
    bool exec;
};

struct ImportSlot {
    uint64_t slot_va = 0;   // IAT 槽位虚拟地址
    std::string dll;        // 例如 KERNEL32
    std::string name;       // 例如 QueryPerformanceCounter
};

struct PeImage {
    std::vector<uint8_t> data;
    uint64_t image_base = 0;
    uint32_t entry_rva = 0;
    uint32_t size_of_image = 0;
    std::vector<Section> sections;
    std::vector<std::pair<uint64_t, uint32_t>> functions;  // va, size
    std::vector<ImportSlot> imports;                       // IAT 表
    uint64_t guard_check_va = 0;                           // Load Config: GuardCFCheckFunctionPointer
    uint64_t guard_dispatch_va = 0;                        // Load Config: GuardCFDispatchFunctionPointer
    std::vector<uint64_t> gfids;                           // Load Config: GFIDS 合法间接目标
    const Section* byRva(uint32_t rva) const;
    const ImportSlot* importBySlot(uint64_t slot_va) const;
    bool hasFunction(uint64_t va) const;
};

bool loadPe(const char* path, PeImage& out, std::string* err);

// 转译选项
enum LiftFlags : uint32_t {
    LIFT_ALLOW_CALL   = 1u << 0,  // 三路 call 路由
    LIFT_STUB_UNKNOWN = 1u << 1,  // 未实现助记符 -> UNIMPL_INSN 占位（保证全量可编译）
    LIFT_TAIL_JUMP    = 1u << 2,
    LIFT_FRAGMENT     = 1u << 3,  // 片段模式：跳出范围的跳转改成 dispatch 并登记为目标入口  // jmp rel32 视为尾调用
};

struct LiftResult {
    bool ok = false;
    std::string code;
    std::vector<std::string> unsupported;
    int insnCount = 0;
    bool usesRipData = false;
    bool hasCall = false;
    bool usesMemory = false;
    bool writesMemory = false;
    bool hasPrologue = false;
    bool usesNonStackMem = false;
    bool fallsOffEnd = false;
    uint32_t ptrArgMask = 0;
    bool badMemBase = false;
    std::string lastMnemonic;
    int directCalls = 0;    // call rel32 且目标在函数表内
    bool indirectCall = false;
    bool iatCall = false;
    bool stubbed = false;   // 含 UNIMPL_INSN 占位
};

// 阶段 2 的严格形态（不改语义）
LiftResult liftFunction(const PeImage& pe, uint64_t va, uint32_t size);
// 阶段 3 的放行形态
LiftResult liftFunctionEx(const PeImage& pe, uint64_t va, uint32_t size, uint32_t flags);

bool registerInputsOk(const PeImage& pe, uint64_t va, uint32_t size);
bool controlFlowClosed(const PeImage& pe, uint64_t va, uint32_t size);

bool pickPureFunction(const PeImage& pe, size_t minSize, size_t maxSize,
                      std::vector<std::pair<uint64_t, uint32_t>>& out,
                      std::vector<uint32_t>* masks = nullptr);

// 阶段 4 中型候选：5–20 个直接调用、读 .rdata、调用闭包可完整转译且不含 IAT/间接调用
struct NestedCand {
    uint64_t va = 0;
    uint32_t size = 0;
    int directCalls = 0;
    size_t closure = 0;
    uint32_t ptr_mask = 0;
};
bool pickNestedCandidate(const PeImage& pe, NestedCand* out,
                         std::vector<std::pair<uint64_t, uint32_t>>* closure,
                         size_t skip = 0);

// 查找字符串及其在代码中的引用（返回 {字符串VA, 引用它的函数VA} 列表）
std::vector<std::pair<uint64_t, uint64_t>> findStringRefs(const PeImage& pe, const char* needle);

// 查找 call rel32 目标为 VA 的函数
std::vector<uint64_t> findCallers(const PeImage& pe, uint64_t target_va);

// 数据段里指向 .text 的函数指针补登为额外入口（处理 CRT 初始化表 / C++ 虚表 / 冷片段）
size_t expandFunctionListByDataPointers(PeImage& pe);

// 阶段 3：分片生成
struct ShardStats {
    size_t total = 0, ok = 0, stubbed = 0, failed = 0;
    size_t shards = 0;
    std::map<std::string, size_t> failReasons;
};
void emitShardSet(const PeImage& pe, int shards, const std::string& outDir,
                  const std::vector<std::pair<uint64_t, uint32_t>>* only,
                  ShardStats* stats);
