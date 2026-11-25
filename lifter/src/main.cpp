// 阶段 2/3 转译器 CLI
//   mew_lifter --pick --exe X.exe                     阶段 2 纯函数候选
//   mew_lifter --lift VA --exe X.exe --out f.cpp      单函数严格转译
//   mew_lifter --pick-nested --exe X.exe --out f.txt  阶段 4 中型嵌套候选 + 闭包
//   mew_lifter --shards 64 --out-dir DIR --exe X.exe  阶段 3 分片全量生成
//   mew_lifter --funcs --exe X.exe                    列出 .pdata 函数
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "lifter_core.h"

namespace {

std::vector<std::pair<uint64_t, uint32_t>> readOnlyList(const std::string& path) {
    std::vector<std::pair<uint64_t, uint32_t>> v;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        const char* p = line.c_str();
        char* end = nullptr;
        unsigned long long va = std::strtoull(p, &end, 0);
        if (end == p) continue;
        uint32_t size = (uint32_t)std::strtoul(end, &end, 10);
        if (size) v.emplace_back((uint64_t)va, size);
    }
    return v;
}

}  // namespace

int main(int argc, char** argv) {
    std::string exe, outPath, mode, outDir, onlyPath, needle, seedsPath;
    uint64_t va = 0;
    int shards = 0;
    size_t skip = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--exe" && i + 1 < argc) exe = argv[++i];
        else if (a == "--out" && i + 1 < argc) outPath = argv[++i];
        else if (a == "--out-dir" && i + 1 < argc) outDir = argv[++i];
        else if (a == "--seeds" && i + 1 < argc) seedsPath = argv[++i];
        else if (a == "--only" && i + 1 < argc) onlyPath = argv[++i];
        else if (a == "--shards" && i + 1 < argc) { mode = "shards"; shards = std::atoi(argv[++i]); }
        else if (a == "--pick") mode = "pick";
        else if (a == "--pick-nested") mode = "pick-nested";
        else if (a == "--skip" && i + 1 < argc) skip = (size_t)std::atoi(argv[++i]);
        else if (a == "--lift" && i + 1 < argc) { mode = "lift"; va = std::strtoull(argv[++i], nullptr, 0); }
        else if (a == "--funcs") mode = "funcs";
        else if (a == "--find-string" && i + 1 < argc) { mode = "find-string"; needle = argv[++i]; }
        else if (a == "--stub-hist") mode = "stub-hist";
        else if (a == "--find-callers" && i + 1 < argc) { mode = "find-callers"; va = std::strtoull(argv[++i], nullptr, 0); }
    }
    if (exe.empty()) { std::fprintf(stderr, "need --exe\n"); return 2; }

    PeImage pe;
    std::string err;
    if (!loadPe(exe.c_str(), pe, &err)) { std::fprintf(stderr, "load failed: %s\n", err.c_str()); return 1; }
    std::printf("image_base=0x%llx functions=%zu sections=%zu imports=%zu\n",
                (unsigned long long)pe.image_base, pe.functions.size(), pe.sections.size(),
                pe.imports.size());

    if (mode == "pick") {
        std::vector<std::pair<uint64_t, uint32_t>> cands;
        std::vector<uint32_t> masks;
        pickPureFunction(pe, 32, 400, cands, &masks);
        std::printf("pure candidates: %zu\n", cands.size());
        for (size_t i = 0; i < cands.size(); ++i) {
            LiftResult r = liftFunction(pe, cands[i].first, cands[i].second);
            std::printf("  va=0x%llx size=%u insns=%d ptr_mask=0x%x badbase=%d\n",
                        (unsigned long long)cands[i].first, cands[i].second, r.insnCount,
                        masks[i], (int)r.badMemBase);
        }
        if (!cands.empty()) {
            std::ofstream o("generated/picked.txt");
            for (size_t i = 0; i < cands.size(); ++i)
                o << std::hex << cands[i].first << " " << std::dec << cands[i].second << " "
                  << std::hex << masks[i] << "\n";
        }
        return cands.empty() ? 1 : 0;
    }

    if (mode == "pick-nested") {
        NestedCand cand;
        std::vector<std::pair<uint64_t, uint32_t>> closure;
        if (!pickNestedCandidate(pe, &cand, &closure, skip)) {
            std::printf("nested candidates: 0\n");
            return 1;
        }
        std::printf("nested candidate va=0x%llx size=%u direct=%d closure=%zu\n",
                    (unsigned long long)cand.va, cand.size, cand.directCalls, closure.size());
        std::string path = outPath.empty() ? "generated/nested.txt" : outPath;
        std::ofstream o(path);
        char maskbuf[32];
        std::snprintf(maskbuf, sizeof(maskbuf), "0x%x", cand.ptr_mask);
        o << "# root va=0x" << std::hex << cand.va << std::dec << " size=" << cand.size
          << " direct=" << cand.directCalls << " closure=" << closure.size()
          << " mask=" << maskbuf << "\n";
        for (auto& c : closure) o << "0x" << std::hex << c.first << std::dec << " " << c.second << "\n";
        o.close();
        std::printf("wrote %s (%zu closure funcs)\n", path.c_str(), closure.size());
        return 0;
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

    if (mode == "shards") {
        if (outDir.empty()) { std::fprintf(stderr, "need --out-dir\n"); return 2; }
        if (!seedsPath.empty()) {
            std::vector<uint64_t> seeds;
            std::ifstream sf(seedsPath);
            std::string line;
            while (std::getline(sf, line)) {
                if (line.empty() || line[0] == '#') continue;
                seeds.push_back(std::strtoull(line.c_str(), nullptr, 0));
            }
            std::printf("seeds loaded=%zu\n", seeds.size());
            addExtraEntries(pe, seeds);
        }
        expandFunctionListByDataPointers(pe);
        std::vector<std::pair<uint64_t, uint32_t>> only;
        std::vector<std::pair<uint64_t, uint32_t>>* onlyPtr = nullptr;
        if (!onlyPath.empty()) { only = readOnlyList(onlyPath); onlyPtr = &only; }
        ShardStats st;
        emitShardSet(pe, shards, outDir, onlyPtr, &st);
        std::printf("shards=%zu total=%zu ok=%zu stubbed=%zu failed=%zu\n",
                    st.shards, st.total, st.ok, st.stubbed, st.failed);
        return 0;
    }

    if (mode == "find-string") {
        auto refs = findStringRefs(pe, needle.c_str());
        std::printf("refs=%zu\n", refs.size());
        for (auto& r : refs)
            std::printf("  str=0x%llx referenced_by=0x%llx\n",
                        (unsigned long long)r.first, (unsigned long long)r.second);
        return refs.empty() ? 1 : 0;
    }

    if (mode == "stub-hist") {
        std::map<std::string, size_t> hist;
        size_t stubFns = 0, total = 0;
        expandFunctionListByDataPointers(pe);
        stubHistogram(pe, hist, &stubFns, &total);
        std::vector<std::pair<std::string, size_t>> v(hist.begin(), hist.end());
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        std::printf("total_functions=%zu stubbed_functions=%zu distinct_stub_mnemonics=%zu\n",
                    total, stubFns, v.size());
        int shown = 0;
        for (const auto& kv : v) {
            if (shown++ >= 40) break;
            std::printf("  %-14s %zu\n", kv.first.c_str(), kv.second);
        }
        return 0;
    }

    if (mode == "find-callers") {
        auto callers = findCallers(pe, va);
        std::printf("callers=%zu\n", callers.size());
        for (auto c : callers)
            std::printf("  caller=0x%llx -> 0x%llx\n", (unsigned long long)c, (unsigned long long)va);
        return callers.empty() ? 1 : 0;
    }

    if (mode == "funcs") {
        for (auto& fn : pe.functions)
            std::printf("%llx %u\n", (unsigned long long)fn.first, fn.second);
        return 0;
    }
    return 0;
}
