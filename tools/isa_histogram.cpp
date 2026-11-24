// 阶段 1：真实指令直方图（Zydis 线性扫描 .text）
// 用法：isa_histogram Mewgenics.exe generated/isa_histogram.json
#include <Zydis/Zydis.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

struct Section {
    std::string name;
    uint32_t va, vsize, raw, rawsize;
};

bool readFile(const char* path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    out.resize((size_t)n);
    size_t got = std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return got == out.size();
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <exe> [out.json]\n", argv[0]);
        return 2;
    }
    const char* outPath = argc > 2 ? argv[2] : "generated/isa_histogram.json";
    std::vector<uint8_t> file;
    if (!readFile(argv[1], file)) {
        std::fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    if (file.size() < 0x100) return 1;

    const uint32_t peOff = *reinterpret_cast<uint32_t*>(file.data() + 0x3c);
    if (std::memcmp(file.data() + peOff, "PE\0\0", 4) != 0) {
        std::fprintf(stderr, "not a PE\n");
        return 1;
    }
    const uint16_t nsec = *reinterpret_cast<uint16_t*>(file.data() + peOff + 6);
    const uint16_t optSize = *reinterpret_cast<uint16_t*>(file.data() + peOff + 20);
    const size_t secTab = peOff + 24 + optSize;

    std::vector<Section> secs;
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint8_t* p = file.data() + secTab + i * 40;
        Section s;
        char name[9] = {0};
        std::memcpy(name, p, 8);
        s.name = name;
        s.vsize = *reinterpret_cast<const uint32_t*>(p + 8);
        s.va = *reinterpret_cast<const uint32_t*>(p + 12);
        s.rawsize = *reinterpret_cast<const uint32_t*>(p + 16);
        s.raw = *reinterpret_cast<const uint32_t*>(p + 20);
        secs.push_back(s);
    }

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::map<std::string, uint64_t> hist;
    uint64_t total = 0, decodeFail = 0, bytesScanned = 0;

    for (const auto& s : secs) {
        if (s.name != ".text") continue;
        if (s.raw + s.rawsize > file.size()) continue;
        const uint8_t* code = file.data() + s.raw;
        size_t size = s.rawsize;
        size_t off = 0;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        while (off < size) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, size - off, &insn, ops))) {
                ++decodeFail;
                off += 1;
                continue;
            }
            const char* mn = ZydisMnemonicGetString(insn.mnemonic);
            hist[mn ? mn : "?"]++;
            ++total;
            off += insn.length;
            bytesScanned += insn.length;
        }
    }

    FILE* f = std::fopen(outPath, "w");
    if (!f) {
        std::fprintf(stderr, "cannot write %s\n", outPath);
        return 1;
    }
    std::fprintf(f, "{\n  \"instructions\": %llu,\n  \"decode_failures\": %llu,\n  \"bytes\": %llu,\n  \"mnemonics\": {",
                 (unsigned long long)total, (unsigned long long)decodeFail, (unsigned long long)bytesScanned);
    bool first = true;
    for (const auto& kv : hist) {
        std::fprintf(f, "%s\n    \"%s\": %llu", first ? "" : ",", kv.first.c_str(), (unsigned long long)kv.second);
        first = false;
    }
    std::fprintf(f, "\n  }\n}\n");
    std::fclose(f);

    std::printf("instructions=%llu decode_failures=%llu mnemonics=%zu\n",
                (unsigned long long)total, (unsigned long long)decodeFail, hist.size());
    int shown = 0;
    for (const auto& kv : hist) {
        if (shown++ >= 15) break;
    }
    return 0;
}
