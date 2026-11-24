// 阶段 2/3 的转译器 CLI
//   mew_lifter --pick Mewgenics.exe        列出纯算法候选函数
//   mew_lifter --lift VA --exe Mewgenics.exe --out f.cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include "lifter_core.h"

int main(int argc, char** argv) {
    std::string exe, outPath, mode;
    uint64_t va = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--exe" && i + 1 < argc) exe = argv[++i];
        else if (a == "--out" && i + 1 < argc) outPath = argv[++i];
        else if (a == "--pick") mode = "pick";
        else if (a == "--lift" && i + 1 < argc) { mode = "lift"; va = std::strtoull(argv[++i], nullptr, 0); }
        else if (a == "--funcs") mode = "funcs";
    }
    if (exe.empty()) { std::fprintf(stderr, "need --exe\n"); return 2; }

    PeImage pe;
    std::string err;
    if (!loadPe(exe.c_str(), pe, &err)) { std::fprintf(stderr, "load failed: %s\n", err.c_str()); return 1; }
    std::printf("image_base=0x%llx functions=%zu sections=%zu\n",
                (unsigned long long)pe.image_base, pe.functions.size(), pe.sections.size());

    if (mode == "pick") {
        std::vector<std::pair<uint64_t, uint32_t>> cands;
        pickPureFunction(pe, 32, 400, cands);
        std::printf("pure candidates: %zu\n", cands.size());
        for (auto& c : cands) {
            LiftResult r = liftFunction(pe, c.first, c.second);
            std::printf("  va=0x%llx size=%u insns=%d\n", (unsigned long long)c.first, c.second, r.insnCount);
        }
        if (!cands.empty()) {
            std::ofstream o("generated/picked.txt");
            for (auto& c : cands)
                o << std::hex << c.first << " " << std::dec << c.second << "\n";
        }
        return cands.empty() ? 1 : 0;
    }

    if (mode == "lift") {
        uint32_t size = 0;
        for (auto& fn : pe.functions)
            if (fn.first == va) { size = fn.second; break; }
        if (!size) { std::fprintf(stderr, "va 0x%llx not in .pdata\n", (unsigned long long)va); return 1; }
        LiftResult r = liftFunction(pe, va, size);
        std::printf("lift ok=%d insns=%d unsupported=%zu\n", (int)r.ok, r.insnCount, r.unsupported.size());
        for (auto& u : r.unsupported) std::printf("  unsupported: %s\n", u.c_str());
        if (!r.ok) return 1;
        std::string path = outPath.empty() ? "generated/lifted.cpp" : outPath;
        std::ofstream o(path);
        o << "#include \"x64_runtime.h\"\n#include \"x64_ops.h\"\n\n" << r.code;
        o.close();
        std::printf("wrote %s\n", path.c_str());
        return 0;
    }

    if (mode == "funcs") {
        for (auto& fn : pe.functions)
            std::printf("%llx %u\n", (unsigned long long)fn.first, fn.second);
        return 0;
    }
    return 0;
}
