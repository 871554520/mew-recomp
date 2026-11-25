#include "lifter_core.h"

#include <Zydis/Zydis.h>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

// ---------------- PE ----------------
const Section* PeImage::byRva(uint32_t rva) const {
    for (const auto& s : sections)
        if (rva >= s.va && rva < s.va + std::max(s.vsize, s.rawsize)) return &s;
    return nullptr;
}

const ImportSlot* PeImage::importBySlot(uint64_t slot_va) const {
    for (const auto& im : imports)
        if (im.slot_va == slot_va) return &im;
    return nullptr;
}

bool PeImage::hasFunction(uint64_t va) const {
    // functions 按 VA 升序（.pdata 本身有序），二分
    size_t lo = 0, hi = functions.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (functions[mid].first < va) lo = mid + 1; else hi = mid;
    }
    return lo < functions.size() && functions[lo].first == va;
}

bool loadPe(const char* path, PeImage& pe, std::string* err) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { if (err) *err = "open failed"; return false; }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    pe.data.resize((size_t)n);
    size_t got = std::fread(pe.data.data(), 1, pe.data.size(), f);
    std::fclose(f);
    if (got != pe.data.size()) { if (err) *err = "short read"; return false; }

    const uint32_t peOff = *(uint32_t*)(pe.data.data() + 0x3c);
    if (std::memcmp(pe.data.data() + peOff, "PE\0\0", 4) != 0) { if (err) *err = "not PE"; return false; }
    const uint16_t nsec = *(uint16_t*)(pe.data.data() + peOff + 6);
    const uint16_t optSize = *(uint16_t*)(pe.data.data() + peOff + 20);
    const uint8_t* opt = pe.data.data() + peOff + 24;
    pe.image_base = *(uint64_t*)(opt + 24);
    pe.entry_rva = *(uint32_t*)(opt + 16);
    pe.size_of_image = *(uint32_t*)(opt + 56);
    const size_t secTab = peOff + 24 + optSize;
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint8_t* p = pe.data.data() + secTab + i * 40;
        Section s;
        char name[9] = {0};
        std::memcpy(name, p, 8);
        s.name = name;
        s.vsize = *(uint32_t*)(p + 8);
        s.va = *(uint32_t*)(p + 12);
        s.rawsize = *(uint32_t*)(p + 16);
        s.raw = *(uint32_t*)(p + 20);
        s.exec = (*(uint32_t*)(p + 36) & 0x20000000) != 0;
        pe.sections.push_back(s);
    }
    // ---- 导入表（IAT 槽位 -> DLL!API）----
    {
        const uint32_t impRva = *(uint32_t*)(opt + 120);
        const uint32_t impSize = *(uint32_t*)(opt + 124);
        if (impRva && impSize) {
            const Section* isec = pe.byRva(impRva);
            if (isec) {
                uint32_t off = isec->raw + (impRva - isec->va);
                for (int d = 0; d < 512 && off + 20 <= isec->raw + isec->rawsize; ++d, off += 20) {
                    const uint8_t* desc = pe.data.data() + off;
                    uint32_t oft = *(uint32_t*)(desc + 0);
                    uint32_t nameRva = *(uint32_t*)(desc + 12);
                    uint32_t ft = *(uint32_t*)(desc + 16);
                    if (!nameRva && !ft) break;
                    const Section* nsec = pe.byRva(nameRva);
                    if (!nsec) continue;
                    std::string dll((const char*)pe.data.data() + nsec->raw + (nameRva - nsec->va));
                    if (dll.size() > 4 && dll.substr(dll.size() - 4) == ".dll") dll.erase(dll.size() - 4);
                    for (char& c : dll) c = (char)std::toupper((unsigned char)c);
                    uint32_t nameThunk = oft ? oft : ft;
                    const Section* tsec = pe.byRva(nameThunk);
                    const Section* fsec = pe.byRva(ft);
                    if (!tsec || !fsec) continue;
                    uint32_t toff = tsec->raw + (nameThunk - tsec->va);
                    for (uint32_t i = 0;; ++i) {
                        if (toff + 8 > tsec->raw + tsec->rawsize) break;
                        uint64_t ent = *(uint64_t*)(pe.data.data() + toff + i * 8);
                        if (!ent) break;
                        if (ent & (1ull << 63)) continue;  // ordinal
                        uint32_t hn = *(uint32_t*)(pe.data.data() + toff + i * 8);
                        const Section* hsec = pe.byRva(hn);
                        if (!hsec) continue;
                        const char* fnameRaw = (const char*)pe.data.data() + hsec->raw + (hn - hsec->va) + 2;
                        ImportSlot im;
                        im.slot_va = pe.image_base + ft + (uint64_t)i * 8;
                        im.dll = dll;
                        im.name = fnameRaw;
                        pe.imports.push_back(im);
                    }
                }
            }
        }
    }

    for (const auto& s : pe.sections) {
        if (s.name != ".pdata") continue;
        const uint8_t* raw = pe.data.data() + s.raw;
        for (uint32_t off = 0; off + 12 <= s.rawsize; off += 12) {
            uint32_t b = *(uint32_t*)(raw + off);
            uint32_t e = *(uint32_t*)(raw + off + 4);
            if (b && e > b) pe.functions.emplace_back(pe.image_base + b, e - b);
        }
    }
    return true;
}

// ---------------- helpers ----------------
namespace {

const char* ctype(int bytes) {
    switch (bytes) {
        case 1: return "uint8_t";
        case 2: return "uint16_t";
        case 4: return "uint32_t";
        default: return "uint64_t";
    }
}

int gprId(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH: return 0;
        case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH: return 1;
        case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH: return 2;
        case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH: return 3;
        case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: return 4;
        case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP: return 5;
        case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: return 6;
        case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: return 7;
        case ZYDIS_REGISTER_R8: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B: return 8;
        case ZYDIS_REGISTER_R9: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B: return 9;
        case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return 10;
        case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return 11;
        case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return 12;
        case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return 13;
        case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return 14;
        case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return 15;
        default: return -1;
    }
}

int xmmId(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_XMM0: return 0; case ZYDIS_REGISTER_XMM1: return 1;
        case ZYDIS_REGISTER_XMM2: return 2; case ZYDIS_REGISTER_XMM3: return 3;
        case ZYDIS_REGISTER_XMM4: return 4; case ZYDIS_REGISTER_XMM5: return 5;
        case ZYDIS_REGISTER_XMM6: return 6; case ZYDIS_REGISTER_XMM7: return 7;
        case ZYDIS_REGISTER_XMM8: return 8; case ZYDIS_REGISTER_XMM9: return 9;
        case ZYDIS_REGISTER_XMM10: return 10; case ZYDIS_REGISTER_XMM11: return 11;
        case ZYDIS_REGISTER_XMM12: return 12; case ZYDIS_REGISTER_XMM13: return 13;
        case ZYDIS_REGISTER_XMM14: return 14; case ZYDIS_REGISTER_XMM15: return 15;
        default: return -1;
    }
}

struct Emit {
    std::ostringstream out;
    std::vector<std::string> unsupported;
    int count = 0;
    bool usesRipData = false;
    bool hasCall = false;
    bool usesMemory = false;
    bool writesMemory = false;
    bool hasPrologue = false;
    bool usesNonStackMem = false;
    bool fallsOffEnd = false;
    uint32_t ptrArgMask = 0;
    bool badMemBase = false;
    uint32_t flags = 0;
    int directCalls = 0;
    bool indirectCall = false;
    bool iatCall = false;
    bool stubbed = false;
};

std::string addrExpr(const PeImage& pe, const ZydisDecodedOperand& op, uint64_t next_rip, Emit& e) {
    if (op.mem.base == ZYDIS_REGISTER_RIP) {
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        e.usesRipData = true;
        return std::to_string((unsigned long long)(next_rip + d)) + "ULL /*rip*/";
    }
    // 段前缀：gs:[disp] / fs:[disp] 走伪 TEB
    if (op.mem.segment == ZYDIS_REGISTER_GS || op.mem.segment == ZYDIS_REGISTER_FS) {
        int64_t sd = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        std::string base = (op.mem.segment == ZYDIS_REGISTER_GS) ? "ctx->gs_base" : "ctx->fs_base";
        std::ostringstream ss;
        ss << "(" << base;
        if (sd >= 0) ss << " + (" << sd << "LL)";
        else ss << " - (" << (-sd) << "LL)";
        ss << ")";
        return ss.str();
    }
    // 内存基址性质分析：栈(rsp/rbp)、参数指针(rcx/rdx/r8/r9)、还是不可判定的寄存器
    {
        auto argIdxOf = [](ZydisRegister r) -> int {
            switch (r) {
                case ZYDIS_REGISTER_RCX: return 0;
                case ZYDIS_REGISTER_RDX: return 1;
                case ZYDIS_REGISTER_R8:  return 2;
                case ZYDIS_REGISTER_R9:  return 3;
                default: return -1;
            }
        };
        ZydisRegister b = op.mem.base, ix = op.mem.index;
        int bi = argIdxOf(b), ii = argIdxOf(ix);
        if (bi >= 0) e.ptrArgMask |= (1u << bi);
        if (ii >= 0) e.ptrArgMask |= (1u << ii);
        bool stackBase = (b == ZYDIS_REGISTER_RSP || b == ZYDIS_REGISTER_RBP || b == ZYDIS_REGISTER_NONE);
        if (!stackBase && bi < 0) { e.badMemBase = true; e.usesNonStackMem = true; }
        if (b == ZYDIS_REGISTER_NONE && ix == ZYDIS_REGISTER_NONE) { e.badMemBase = true; e.usesNonStackMem = true; }
        if (ix != ZYDIS_REGISTER_NONE && ii < 0) { e.badMemBase = true; e.usesNonStackMem = true; }
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        if (d < -0x4000 || d > 0x8000) e.badMemBase = true;
    }
    std::ostringstream s;
    bool any = false;
    if (op.mem.base != ZYDIS_REGISTER_NONE) {
        int b = gprId(op.mem.base);
        if (b < 0) return "0";
        s << "read_reg(ctx," << b << ",8)";
        any = true;
    }
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
        int i = gprId(op.mem.index);
        if (i < 0) return "0";
        if (any) s << " + ";
        s << "read_reg(ctx," << i << ",8)*" << (int)op.mem.scale;
        any = true;
    }
    int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
    if (d || !any) {
        if (any) s << " + ";
        s << "(" << d << "LL)";
        any = true;
    }
    (void)pe;
    return s.str();
}

std::string valExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& op,
                    uint64_t next_rip, Emit& e) {
    switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int id = gprId(op.reg.value);
            if (id >= 0) return "read_reg(ctx," + std::to_string(id) + "," + std::to_string(op.size / 8) + ")";
            int xi = xmmId(op.reg.value);
            if (xi >= 0) return "xmm_u64(ctx," + std::to_string(xi) + ")";
            return "0";
        }
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            return std::to_string((unsigned long long)op.imm.value.u) + "ULL";
        case ZYDIS_OPERAND_TYPE_MEMORY:
            return std::string("mem_read<") + ctype(op.size / 8) + ">(ctx," + addrExpr(pe, op, next_rip, e) + ")";
        default:
            return "0";
    }
}

std::string hexStr(uint64_t v);

void storeExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& dst,
               const std::string& val, uint64_t next_rip, int bytes, Emit& e) {
    (void)in;
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int id = gprId(dst.reg.value);
        if (id >= 0) { e.out << "  write_reg(ctx," << id << "," << val << "," << bytes << ");\n"; return; }
        int xi = xmmId(dst.reg.value);
        if (xi >= 0) { e.out << "  xmm_set_u64(ctx," << xi << "," << val << ");\n"; return; }
        if (e.flags & LIFT_STUB_UNKNOWN) {
            e.stubbed = true;
            e.out << "  UNIMPL_INSN(0x" << hexStr(next_rip) << "ULL, \"reg-store\");\n";
            return;
        }
        e.unsupported.push_back("reg-store");
        return;
    }
    if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        e.writesMemory = true;
        e.out << "  mem_write<" << ctype(bytes) << ">(ctx," << addrExpr(pe, dst, next_rip, e) << "," << val << ");\n";
        return;
    }
    e.unsupported.push_back("store");
}

std::string canonCC(const std::string& suf) {
    if (suf == "e" || suf == "z") return "z";
    if (suf == "ne" || suf == "nz") return "nz";
    if (suf == "s") return "s";
    if (suf == "ns") return "ns";
    if (suf == "c" || suf == "b" || suf == "nae") return "b";
    if (suf == "nc" || suf == "ae" || suf == "nb") return "ae";
    if (suf == "be" || suf == "na") return "be";
    if (suf == "a" || suf == "nbe") return "a";
    if (suf == "l" || suf == "nge") return "l";
    if (suf == "ge" || suf == "nl") return "ge";
    if (suf == "le" || suf == "ng") return "le";
    if (suf == "g" || suf == "nle") return "g";
    if (suf == "o") return "o";
    if (suf == "no") return "no";
    if (suf == "p" || suf == "pe") return "p";
    if (suf == "np" || suf == "po") return "np";
    return "";
}

std::string ccByCanon(const std::string& c) {
    if (c == "z") return "ctx->zf";
    if (c == "nz") return "!ctx->zf";
    if (c == "s") return "ctx->sf";
    if (c == "ns") return "!ctx->sf";
    if (c == "b") return "ctx->cf";
    if (c == "ae") return "!ctx->cf";
    if (c == "be") return "(ctx->cf || ctx->zf)";
    if (c == "a") return "(!ctx->cf && !ctx->zf)";
    if (c == "l") return "(ctx->sf != ctx->of)";
    if (c == "ge") return "(ctx->sf == ctx->of)";
    if (c == "le") return "(ctx->zf || (ctx->sf != ctx->of))";
    if (c == "g") return "(!ctx->zf && (ctx->sf == ctx->of))";
    if (c == "o") return "ctx->of";
    if (c == "no") return "!ctx->of";
    if (c == "p") return "ctx->pf";
    if (c == "np") return "!ctx->pf";
    return "";
}

std::string ccExpr(const std::string& mn) {
    if (mn.size() < 2 || mn[0] != 'j') return "";
    return ccByCanon(canonCC(mn.substr(1)));
}

// setcc / cmovcc 后缀 → 条件表达式
std::string ccSuffix(const std::string& mn, const char* prefix) {
    size_t n = std::strlen(prefix);
    if (mn.rfind(prefix, 0) != 0) return "";
    return ccByCanon(canonCC(mn.substr(n)));
}

std::string hexStr(uint64_t v) { std::ostringstream o; o << std::hex << v; return o.str(); }
std::string shimSym(const ImportSlot& im) { return "shim_" + im.dll + "_" + im.name; }

// 目标若是 `jmp qword ptr [rip+disp]` 形式的 IAT thunk，返回对应导入槽
static const ImportSlot* resolveIatThunk(const PeImage& pe, uint64_t target) {
    const Section* sec = pe.byRva((uint32_t)(target - pe.image_base));
    if (!sec) return nullptr;
    uint32_t off = sec->raw + (uint32_t)(target - pe.image_base - sec->va);
    if (off + 6 > sec->raw + sec->rawsize) return nullptr;
    const uint8_t* p = pe.data.data() + off;
    if (p[0] == 0xFF && p[1] == 0x25) {
        int32_t disp = *(const int32_t*)(p + 2);
        uint64_t slot = target + 6 + (int64_t)disp;
        return pe.importBySlot(slot);
    }
    return nullptr;
}

}  // namespace

LiftResult liftFunction(const PeImage& pe, uint64_t va, uint32_t size) {
    return liftFunctionEx(pe, va, size, 0);
}

LiftResult liftFunctionEx(const PeImage& pe, uint64_t va, uint32_t size, uint32_t flags) {
    LiftResult res;
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) { res.unsupported.push_back("no-section"); return res; }
    const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(va - pe.image_base - sec->va);

    // .pdata 的 size 含尾部 int3/nop 对齐填充；剥掉填充后再判定流程是否收尾
    uint32_t effSize = size;
    while (effSize > 0 && (code[effSize - 1] == 0xCC || code[effSize - 1] == 0x90)) --effSize;
    if (effSize == 0) { res.unsupported.push_back("all-padding"); return res; }

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // 预扫：线性解码能落到的指令起始地址（分支只能跳进这个集合，否则标签不存在）
    std::unordered_set<uint64_t> labelSet;
    {
        size_t p = 0;
        ZydisDecodedInstruction i2;
        ZydisDecodedOperand o2[ZYDIS_MAX_OPERAND_COUNT];
        while (p < effSize) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + p, effSize - p, &i2, o2))) break;
            labelSet.insert(va + p);
            p += i2.length;
        }
    }

    Emit e;
    e.flags = flags;
    e.out << "void sub_" << std::hex << va << std::dec << "(X64Ctx* ctx) {\n";

    size_t off = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    while (off < effSize) {
        uint64_t rip = va + off;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, effSize - off, &insn, ops))) {
            if (flags & LIFT_STUB_UNKNOWN) {
                e.stubbed = true;
                e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"decode-fail\");\n";
                e.count++;
            } else {
                e.unsupported.push_back("decode-fail");
            }
            break;
        }
        uint64_t next_rip = rip + insn.length;
        const char* m = ZydisMnemonicGetString(insn.mnemonic);
        std::string mn = m ? m : "?";
        e.count++;

        for (uint16_t oi = 0; oi < insn.operand_count; ++oi) {
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.usesMemory = true;
                if (oi == 0) e.writesMemory = true;
            }
        }
        if (e.count == 1) {
            if (mn == "push" ||
                (mn == "sub" && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RSP) ||
                (mn == "mov" && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY)) {
                e.hasPrologue = true;
            }
        }

        e.out << "L_" << std::hex << rip << std::dec << ": ;\n";

        const bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
        const std::string setcc = ccSuffix(mn, "set");
        const std::string cmovcc = ccSuffix(mn, "cmov");

        if (mn == "nop" || mn == "int3" || mn == "endbr64" || mn == "pause") {
            /* no-op */
        } else if (mn == "ret") {
            e.out << "  ctx->rsp += 8; return;\n";
        } else if (mn == "leave") {
            e.out << "  write_reg(ctx,4,read_reg(ctx,5,8),8); write_reg(ctx,5,mem_read<uint64_t>(ctx,ctx->rsp),8); ctx->rsp += 8;\n";
        } else if (mn == "push") {
            e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, "
                  << valExpr(pe, insn, ops[0], next_rip, e) << ");\n";
        } else if (mn == "pop") {
            storeExpr(pe, insn, ops[0], "mem_read<uint64_t>(ctx,ctx->rsp)", next_rip, 8, e);
            e.out << "  ctx->rsp += 8;\n";
        } else if (mn == "mov" || mn == "movzx" || mn == "movsx" || mn == "movsxd" || mn == "movd" || mn == "movq") {
            std::string v = valExpr(pe, insn, ops[1], next_rip, e);
            if (mn == "movzx") {
                unsigned bits = ops[1].size;
                if (bits < 64) {
                    std::ostringstream t;
                    t << std::hex << ((1ULL << bits) - 1);
                    v = "(" + v + " & 0x" + t.str() + "ULL)";
                }
            } else if (mn == "movsx" || mn == "movsxd") {
                v = "(uint64_t)(int64_t)(int" + std::to_string(ops[1].size) + "_t)(" + v + ")";
            }
            storeExpr(pe, insn, ops[0], v, next_rip, ops[0].size / 8, e);
        } else if (mn == "lea") {
            storeExpr(pe, insn, ops[0], addrExpr(pe, ops[1], next_rip, e), next_rip, ops[0].size / 8, e);
        } else if (mn == "add" || mn == "sub" || mn == "cmp" || mn == "and" || mn == "or" ||
                   mn == "xor" || mn == "test") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = valExpr(pe, insn, ops[1], next_rip, e);
            int w = ops[0].size / 8;
            std::string call;
            if (mn == "add") call = "add_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            else if (mn == "sub" || mn == "cmp") call = "sub_flags(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            else {
                std::string opx = (mn == "and" || mn == "test") ? "&" : (mn == "or") ? "|" : "^";
                call = "logic_flags(ctx,(" + a + " " + opx + " " + b + ")," + std::to_string(w) + ")";
            }
            if (mn == "cmp" || mn == "test") e.out << "  (void)" << call << ";\n";
            else storeExpr(pe, insn, ops[0], call, next_rip, w, e);
        } else if (mn == "inc" || mn == "dec") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            int w = ops[0].size / 8;
            std::string call = (mn == "inc") ? "add_flags(ctx," + a + ",1ULL," + std::to_string(w) + ")"
                                             : "sub_flags(ctx," + a + ",1ULL," + std::to_string(w) + ")";
            storeExpr(pe, insn, ops[0], call, next_rip, w, e);
        } else if (mn == "neg") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            int w = ops[0].size / 8;
            storeExpr(pe, insn, ops[0], "sub_flags(ctx,0ULL," + a + "," + std::to_string(w) + ")", next_rip, w, e);
        } else if (mn == "not") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            storeExpr(pe, insn, ops[0], "(~" + a + ")", next_rip, ops[0].size / 8, e);
        } else if (mn == "cdqe" || mn == "cwde" || mn == "cbw" || mn == "cdq" || mn == "cqo" || mn == "cwd") {
            if (mn == "cdqe") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int32_t)read_reg(ctx,0,4),8);\n";
            else if (mn == "cwde") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int16_t)read_reg(ctx,0,2),4);\n";
            else if (mn == "cbw") e.out << "  write_reg(ctx,0,(uint64_t)(int64_t)(int8_t)read_reg(ctx,0,1),2);\n";
            else if (mn == "cdq") e.out << "  write_reg(ctx,2,(uint64_t)(int64_t)((int64_t)(int32_t)read_reg(ctx,0,4) >> 31),4);\n";
            else e.out << "  write_reg(ctx,2,(uint64_t)((int64_t)read_reg(ctx,0,8) >> 63),8);\n";
        } else if (mn == "imul") {
            if (insn.operand_count == 1) {
                e.out << "  { int64_t x=(int64_t)read_reg(ctx,0,8), y=(int64_t)"
                      << valExpr(pe, insn, ops[0], next_rip, e) << "; __int128 p=(__int128)x*y;"
                         " write_reg(ctx,0,(uint64_t)p,8); write_reg(ctx,2,(uint64_t)(p>>64),8); }\n";
            } else if (insn.operand_count == 2) {
                int id = gprId(ops[0].reg.value);
                e.out << "  write_reg(ctx," << id << ",(uint64_t)((int64_t)read_reg(ctx," << id << ",8) * (int64_t)"
                      << valExpr(pe, insn, ops[1], next_rip, e) << ")," << ops[0].size / 8 << ");\n";
            } else {
                int id = gprId(ops[0].reg.value);
                e.out << "  write_reg(ctx," << id << ",(uint64_t)((int64_t)"
                      << valExpr(pe, insn, ops[1], next_rip, e) << " * (int64_t)"
                      << valExpr(pe, insn, ops[2], next_rip, e) << ")," << ops[0].size / 8 << ");\n";
            }
        } else if (mn == "shl" || mn == "shr" || mn == "sar") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = (insn.operand_count > 1) ? valExpr(pe, insn, ops[1], next_rip, e) : "1ULL";
            int w = ops[0].size / 8;
            std::string shift = (mn == "shl") ? "<<" : ">>";
            if (mn == "sar") {
                storeExpr(pe, insn, ops[0],
                          "(uint64_t)((int64_t)(" + a + ") >> (" + b + " & 63))", next_rip, w, e);
            } else {
                storeExpr(pe, insn, ops[0], "((" + a + ") " + shift + " (" + b + " & 63))", next_rip, w, e);
            }
        } else if (mn == "rol" || mn == "ror") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = (insn.operand_count > 1) ? valExpr(pe, insn, ops[1], next_rip, e) : "1ULL";
            int w = ops[0].size / 8;
            int bits = w * 8;
            std::string fn = (mn == "rol") ? "rotl" : "rotr";
            storeExpr(pe, insn, ops[0], std::string(fn) + "<uint64_t>(" + a + "," + b + ") & " +
                                     std::to_string(bits == 64 ? ~0ULL : ((1ULL << bits) - 1)) + "ULL",
                      next_rip, w, e);
        } else if (mn == "bswap") {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            e.out << "  write_reg(ctx," << gprId(ops[0].reg.value) << ",bswap64(" << a << "),8);\n";
        } else if (mn == "jmp") {
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t >= va && t < va + effSize) {
                    if (labelSet.count(t)) {
                        e.out << "  goto L_" << hexStr(t) << ";\n";
                    } else if (flags & LIFT_STUB_UNKNOWN) {
                        e.stubbed = true;
                        e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-missing\");\n";
                    } else {
                        e.unsupported.push_back("jump-missing");
                        break;
                    }
                } else if (flags & LIFT_TAIL_JUMP) {
                    // 尾调用：不压模拟返回地址，直接跳/返回
                    if (pe.hasFunction(t)) {
                        e.out << "  return sub_" << hexStr(t) << "(ctx);\n";
                    } else if (const ImportSlot* im = resolveIatThunk(pe, t)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); return;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx); return;\n";
                    }
                } else { e.unsupported.push_back("jump-out-of-func"); break; }
            } else if (flags & LIFT_TAIL_JUMP) {
                if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t slot = next_rip + (int64_t)ops[0].mem.disp.value;
                    if (const ImportSlot* im = pe.importBySlot(slot)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); return;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(mem_read<uint64_t>(ctx,0x" << hexStr(slot) << "ULL), ctx); return;\n";
                    }
                } else {
                    e.indirectCall = true;
                    e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx); return;\n";
                }
            } else {
                e.unsupported.push_back("jmp-indirect");
            }
        } else if (mn == "jrcxz" || mn == "jecxz" || mn == "jcxz") {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            std::string cond = (mn == "jrcxz") ? "(read_reg(ctx,1,8) == 0)"
                             : (mn == "jecxz") ? "(read_reg(ctx,1,4) == 0)"
                                               : "(read_reg(ctx,1,2) == 0)";
            if (t >= va && t < va + effSize && labelSet.count(t)) {
                e.out << "  if (" << cond << ") goto L_" << hexStr(t) << ";\n";
            } else if (flags & LIFT_STUB_UNKNOWN) {
                e.stubbed = true;
                e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"" << mn << "\");\n";
            } else {
                e.unsupported.push_back(mn);
            }
        } else if (isJcc) {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            std::string cond = ccExpr(mn);
            if (t >= va && t < va + effSize && !labelSet.count(t)) {
                if (flags & LIFT_STUB_UNKNOWN) {
                    e.stubbed = true;
                    e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"jump-missing\");\n";
                } else {
                    e.unsupported.push_back("jump-missing");
                }
                off += insn.length;
                continue;
            }
            if (t < va || t >= va + effSize) {
                if ((flags & LIFT_TAIL_JUMP) && pe.hasFunction(t)) {
                    if (cond.empty()) { e.unsupported.push_back(mn); break; }
                    // 目标在另一块：cond 成立即尾跳进冷片段
                    e.out << "  if (" << cond << ") return sub_" << hexStr(t) << "(ctx);\n";
                    off += insn.length;
                    continue;
                }
                e.unsupported.push_back("jump-out-of-func"); break;
            }
            if (cond.empty()) { e.unsupported.push_back(mn); break; }
            e.out << "  if (" << cond << ") goto L_" << std::hex << t << std::dec << ";\n";
        } else if (!setcc.empty()) {
            storeExpr(pe, insn, ops[0], "((uint64_t)(" + setcc + "))", next_rip, 1, e);
        } else if (!cmovcc.empty()) {
            std::string a = valExpr(pe, insn, ops[0], next_rip, e);
            std::string b = valExpr(pe, insn, ops[1], next_rip, e);
            storeExpr(pe, insn, ops[0], "((" + cmovcc + ") ? " + b + " : " + a + ")", next_rip, ops[0].size / 8, e);
        } else if (mn == "call") {
            e.hasCall = true;
            if (!(flags & LIFT_ALLOW_CALL)) {
                e.unsupported.push_back("call");
            } else {
                const auto pushRet = [&]() {
                    e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, 0x"
                          << hexStr(next_rip) << "ULL);\n";
                };
                if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                    pushRet();
                    if (pe.hasFunction(t)) {
                        e.directCalls++;
                        e.out << "  sub_" << hexStr(t) << "(ctx);\n";
                    } else if (const ImportSlot* im = resolveIatThunk(pe, t)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(0x" << hexStr(t) << "ULL, ctx);\n";
                    }
                } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                    uint64_t slot = next_rip + (int64_t)ops[0].mem.disp.value;
                    pushRet();
                    if (const ImportSlot* im = pe.importBySlot(slot)) {
                        e.iatCall = true;
                        e.out << "  " << shimSym(*im) << "(ctx); ctx->rsp += 8;\n";
                    } else {
                        e.indirectCall = true;
                        e.out << "  dispatch_indirect(mem_read<uint64_t>(ctx,0x" << hexStr(slot) << "ULL), ctx);\n";
                    }
                } else {
                    pushRet();
                    e.indirectCall = true;
                    e.out << "  dispatch_indirect(" << valExpr(pe, insn, ops[0], next_rip, e) << ", ctx);\n";
                }
            }
        } else if (flags & LIFT_STUB_UNKNOWN) {
            e.stubbed = true;
            e.out << "  UNIMPL_INSN(0x" << hexStr(rip) << "ULL, \"" << mn << "\");\n";
        } else {
            e.unsupported.push_back(mn);
        }

        if (!e.unsupported.empty()) break;
        off += insn.length;
    }

    // 末尾必须收尾：ret / jmp / 已 unsupported；否则执行会流到函数外（真机进入下一函数字节或 int3）
    if (e.unsupported.empty()) {
        bool terminated = false;
        {
            const char* m2 = ZydisMnemonicGetString(insn.mnemonic);
            std::string last = m2 ? m2 : "?";
            res.lastMnemonic = last;
            terminated = (last == "ret" || last == "jmp");
        }
        if (!terminated) e.fallsOffEnd = true;
    }
    if (e.unsupported.empty()) e.out << "}\n";
    res.ok = e.unsupported.empty() && e.count > 0;
    res.code = e.out.str();
    res.unsupported = e.unsupported;
    res.insnCount = e.count;
    res.usesRipData = e.usesRipData;
    res.hasCall = e.hasCall;
    res.usesMemory = e.usesMemory;
    res.writesMemory = e.writesMemory;
    res.hasPrologue = e.hasPrologue;
    res.usesNonStackMem = e.usesNonStackMem;
    res.fallsOffEnd = e.fallsOffEnd;
    res.ptrArgMask = e.ptrArgMask;
    res.badMemBase = e.badMemBase;
    res.directCalls = e.directCalls;
    res.indirectCall = e.indirectCall;
    res.iatCall = e.iatCall;
    res.stubbed = e.stubbed;
    return res;
}


// 可达性判定：从入口走遍所有路径，任一路径流出 [va, va+size) 就返回 false
bool controlFlowClosed(const PeImage& pe, uint64_t va, uint32_t size) {
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) return false;
    const uint8_t* base = pe.data.data() + sec->raw;
    const uint32_t rva0 = (uint32_t)(va - pe.image_base - sec->va);
    // 剥掉尾部填充
    uint32_t eff = size;
    while (eff > 0) {
        uint8_t b = 0;
        uint32_t o = va + eff - 1 - (uint32_t)pe.image_base - sec->va;
        if (o < sec->rawsize) b = base[o]; else break;
        if (b == 0xCC || b == 0x90) --eff; else break;
    }
    if (eff == 0) return false;
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    std::vector<uint64_t> work{va};
    std::vector<uint64_t> seen;
    while (!work.empty()) {
        uint64_t cur = work.back(); work.pop_back();
        for (uint64_t v : seen) if (v == cur) goto next_item;
        seen.push_back(cur);
        for (;;) {
            if (cur < va || cur >= va + eff) return false;
            uint32_t off = (uint32_t)(cur - va) + rva0;
            if (off >= sec->rawsize || (uint32_t)(cur - va) >= eff) return false;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, base + off,
                    sec->rawsize - off < eff - (uint32_t)(cur - va) ? sec->rawsize - off : eff - (uint32_t)(cur - va),
                    &insn, ops))) return false;
            uint64_t next_rip = cur + insn.length;
            const char* m = ZydisMnemonicGetString(insn.mnemonic);
            std::string mn = m ? m : "?";
            if (mn == "ret") break;
            if (mn == "jmp") {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                if (t < va || t >= va + eff) return false;
                work.push_back(t);
                break;
            }
            bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
            if (isJcc) {
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + eff) return false;
                work.push_back(t);
            } else if (mn == "call") {
                return false;
            }
            cur = next_rip;
            if (cur >= va + eff) return false;  // 非收尾指令淌出函数
        }
    next_item:;
    }
    return true;
}


// 寄存器输入分析：函数只能读取“我们提供的”寄存器（rcx/rdx/r8/r9 + rsp），
// 读取未初始化寄存器（rbx/rsi/rdi/r12-r15/rax/r10/r11/rbp）说明它需要调用方上下文，阶段 2 不可独立调用。
static int gprIdxOf(ZydisRegister r) {
    switch (r) {
        case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_RCX: return 1;
        case ZYDIS_REGISTER_RDX: return 2;
        case ZYDIS_REGISTER_RBX: return 3;
        case ZYDIS_REGISTER_RSP: return 4;
        case ZYDIS_REGISTER_RBP: return 5;
        case ZYDIS_REGISTER_RSI: return 6;
        case ZYDIS_REGISTER_RDI: return 7;
        case ZYDIS_REGISTER_R8:  return 8;
        case ZYDIS_REGISTER_R9:  return 9;
        case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15: return 15;
        default: return -1;
    }
}

static bool writesOnlyOperand0(const std::string& mn) {
    static const char* k[] = {"mov", "movzx", "movsx", "movsxd", "movd", "movq", "lea", "pop",
                              "setcc", "cbw", "cwde", "cdqe", "cdq", "cqo", "cwd", "bswap"};
    for (const char* x : k) if (mn == x) return true;
    return false;
}

bool registerInputsOk(const PeImage& pe, uint64_t va, uint32_t size) {
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) return false;
    const uint8_t* base = pe.data.data() + sec->raw;
    const uint32_t rva0 = (uint32_t)(va - pe.image_base - sec->va);
    uint32_t eff = size;
    while (eff > 0) {
        uint32_t o = va + eff - 1 - (uint32_t)pe.image_base - sec->va;
        if (o >= sec->rawsize) break;
        uint8_t b = base[o];
        if (b == 0xCC || b == 0x90) --eff; else break;
    }
    if (eff == 0) return false;

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    // 位=1 表示“该寄存器当前值未知（来自调用方或未初始化）”
    uint16_t kInit = (uint16_t)(0xFFFFu & ~((1u << 1) | (1u << 2) | (1u << 8) | (1u << 9) | (1u << 4)));
    kInit = (uint16_t)kInit;

    // 工作项：(地址, 进入时的已初始化掩码)
    std::vector<std::pair<uint64_t, uint16_t>> work{{va, kInit}};
    std::vector<std::pair<uint64_t, uint16_t>> seen;
    while (!work.empty()) {
        std::pair<uint64_t, uint16_t> item = work.back(); work.pop_back();
        uint64_t cur = item.first;
        uint16_t init = item.second;
        bool merged = false;
        for (auto& sv : seen) {
            if (sv.first == cur) {
                // 未知掩码：任一路径未知即视为未知（并集，保守）
                uint16_t uni = (uint16_t)(sv.second | init);
                if (uni == sv.second) { merged = true; break; }
                sv.second = uni;
                init = uni;
                break;
            }
        }
        if (merged) continue;
        bool isNew = true;
        for (auto& sv : seen) if (sv.first == cur) { isNew = false; break; }
        if (isNew) seen.push_back({cur, init});

        for (;;) {
            if (cur < va || cur >= va + eff) return false;
            uint32_t rel = (uint32_t)(cur - va);
            uint32_t off = rel + rva0;
            if (off >= sec->rawsize) return false;
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            uint32_t avail = eff - rel;
            if (sec->rawsize - off < avail) avail = sec->rawsize - off;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, base + off, avail, &insn, ops))) return false;
            uint64_t next_rip = cur + insn.length;
            const char* m = ZydisMnemonicGetString(insn.mnemonic);
            std::string mn = m ? m : "?";
            const bool wo0 = writesOnlyOperand0(mn);
            const bool xorSelf = (mn == "xor" || mn == "sub") &&
                insn.operand_count >= 2 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ops[0].reg.value == ops[1].reg.value;
            // ---- 污点检查 ----
            bool srcUnknown = false;
            for (uint16_t oi = 0; oi < insn.operand_count; ++oi) {
                if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    int gb = gprIdxOf(ops[oi].mem.base);
                    int gx = gprIdxOf(ops[oi].mem.index);
                    if (gb >= 0 && (init & (1u << gb))) return false;   // 未知值当地址 -> 会崩
                    if (gx >= 0 && (init & (1u << gx))) return false;
                    continue;
                }
                if (ops[oi].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
                int gi = gprIdxOf(ops[oi].reg.value);
                if (gi < 0) continue;
                bool reads = (oi >= 1) || !(wo0 || xorSelf);
                if (reads && (init & (1u << gi))) srcUnknown = true;
            }
            if (insn.operand_count > 0 && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                int gd = gprIdxOf(ops[0].reg.value);
                if (gd >= 0) {
                    bool destReads = !(wo0 || xorSelf);
                    bool unk = srcUnknown || (destReads && (init & (1u << gd)));
                    if (xorSelf) unk = false;
                    if (unk) init |= (uint16_t)(1u << gd); else init &= (uint16_t)~(1u << gd);
                }
            }
            if (mn == "ret") break;
            if (mn == "jmp") {
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + eff) return false;
                work.push_back({t, init});
                break;
            }
            bool isJcc = (mn.size() > 1 && mn[0] == 'j' && mn != "jmp");
            if (isJcc) {
                if (ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + eff) return false;
                work.push_back({t, init});
            }
            cur = next_rip;
            if (cur >= va + eff) return false;
        }
    }
    return true;
}

bool pickPureFunction(const PeImage& pe, size_t minSize, size_t maxSize,
                      std::vector<std::pair<uint64_t, uint32_t>>& out,
                      std::vector<uint32_t>* masks) {
    out.clear();
    if (masks) masks->clear();
    size_t nSize = 0, nLift = 0, nNoCall = 0, nNoRip = 0, nFramed = 0, nClosed = 0;
    bool capped = false;
    for (const auto& fn : pe.functions) {
        if (fn.second < minSize || fn.second > maxSize) continue;
        ++nSize;
        LiftResult r = liftFunction(pe, fn.first, fn.second);
        if (!r.ok) continue;
        ++nLift;
        if (r.hasCall) continue;
        ++nNoCall;
        if (r.usesRipData) continue;
        ++nNoRip;
        // 纯栈访问要求有正规栈帧；用到参数指针的则无需栈帧
        if (r.usesMemory && r.ptrArgMask == 0 && !r.hasPrologue) continue;
        ++nFramed;
        if (!controlFlowClosed(pe, fn.first, fn.second)) continue;
        if (!registerInputsOk(pe, fn.first, fn.second)) continue;
        ++nClosed;
        out.push_back(fn);
        if (masks) masks->push_back(r.ptrArgMask);
        if (out.size() >= 8) { capped = true; break; }
    }
    fprintf(stderr, "[funnel] size=%zu lift_ok=%zu no_call=%zu no_ripdata=%zu framed=%zu cf_closed=%zu capped=%d\n",
            nSize, nLift, nNoCall, nNoRip, nFramed, nClosed, (int)capped);
    return !out.empty();
}

// ---------------- 阶段 3：分片生成 ----------------
namespace {

std::string hexva(uint64_t v) { std::ostringstream o; o << std::hex << v; return o.str(); }

}  // namespace

bool pickNestedCandidate(const PeImage& pe, NestedCand* out,
                         std::vector<std::pair<uint64_t, uint32_t>>* closure,
                         size_t skip) {
    struct Info { bool ok; bool okNoStub; int direct; bool ind; bool iat; bool rip; uint32_t size;
                  uint32_t ptrMask; bool nonStackMem; bool prologue; std::string last;
                  bool badBase; };
    std::unordered_map<uint64_t, Info> infos;
    infos.reserve(pe.functions.size() * 2);
    std::unordered_map<uint64_t, uint32_t> sizes;
    for (const auto& fn : pe.functions) sizes[fn.first] = fn.second;

    for (const auto& fn : pe.functions) {
        LiftResult r = liftFunctionEx(pe, fn.first, fn.second,
                                      LIFT_ALLOW_CALL | LIFT_TAIL_JUMP);
        Info i;
        i.okNoStub = r.ok && !r.stubbed;
        i.ok = r.ok;
        i.direct = r.directCalls;
        i.ind = r.indirectCall;
        i.iat = r.iatCall;
        i.rip = r.usesRipData;
        i.size = fn.second;
        i.ptrMask = r.ptrArgMask;
        i.nonStackMem = r.usesNonStackMem;
        i.prologue = r.hasPrologue;
        i.last = r.lastMnemonic;
        i.badBase = r.badMemBase;
        infos[fn.first] = i;
    }

    auto collectTargets = [&](uint64_t va, uint32_t size, std::vector<uint64_t>& tgts) {
        const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
        if (!sec) return;
        const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(va - pe.image_base - sec->va);
        ZydisDecoder dec;
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        size_t off = 0;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        while (off < size) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, size - off, &insn, ops))) break;
            uint64_t next_rip = va + off + insn.length;
            // 直接调用 + 跨块尾跳（jmp/jcc 到本函数范围外）都算闭包边
            if ((insn.mnemonic == ZYDIS_MNEMONIC_CALL || insn.mnemonic == ZYDIS_MNEMONIC_JMP) &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + size) {
                    if (pe.hasFunction(t)) tgts.push_back(t);
                }
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       insn.mnemonic >= ZYDIS_MNEMONIC_JB && insn.mnemonic <= ZYDIS_MNEMONIC_JZ) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if ((t < va || t >= va + size) && pe.hasFunction(t)) tgts.push_back(t);
            }
            off += insn.length;
        }
    };

    size_t nRoot = 0, nRip = 0, nDirect = 0, tried = 0, matches = 0;
    struct Near { uint64_t va; int direct; size_t closure; size_t stubbed; bool iat, ind; };
    std::vector<Near> nears;

    for (int pass = 0; pass < 2; ++pass) {
    const bool strict = (pass == 0);
    for (const auto& fn : pe.functions) {
        auto it = infos.find(fn.first);
        if (it == infos.end()) continue;
        const Info& ri = it->second;
        ++nRoot;
        if (strict && (ri.ptrMask != 0 || ri.nonStackMem)) continue;
        if (!ri.ok || !ri.rip || ri.ind) continue;
        ++nRip;
        if (ri.iat) continue;
        if (ri.direct < 3 || ri.direct > 40) continue;
        ++nDirect;
        if (nears.size() < 8) ++tried;

        std::vector<uint64_t> work{fn.first}, seen{fn.first};
        size_t stubbed = 0;
        bool ok = true, hasIat = false, hasInd = false;
        while (!work.empty() && ok) {
            uint64_t cur = work.back(); work.pop_back();
            auto ci = infos.find(cur);
            if (ci == infos.end()) { ok = false; break; }
            if (!ci->second.ok) { ok = false; break; }
            if (!ci->second.okNoStub) ++stubbed;
            if (ci->second.iat) hasIat = true;
            if (ci->second.ind) hasInd = true;
            if (strict) {
                if (ci->second.ptrMask != 0 || ci->second.nonStackMem) { ok = false; break; }
                if (!ci->second.prologue || ci->second.last != "ret") { ok = false; break; }
                if (ci->second.badBase) { ok = false; break; }
            }
            auto sz = sizes.find(cur);
            if (sz == sizes.end()) { ok = false; break; }
            std::vector<uint64_t> tgts;
            collectTargets(cur, sz->second, tgts);
            for (uint64_t t : tgts) {
                bool dup = false;
                for (uint64_t v : seen) if (v == t) { dup = true; break; }
                if (!dup) {
                    seen.push_back(t); work.push_back(t);
                    if (seen.size() > 96) { ok = false; break; }
                }
            }
        }
        if (nears.size() < 8) nears.push_back({fn.first, ri.direct, seen.size(), stubbed, hasIat, hasInd});
        if (!ok) continue;
        if (hasIat || hasInd || stubbed > 0) continue;
        if (seen.size() > 96 || seen.size() < 4) continue;
        if (ri.size < 128) continue;
        if (matches++ < skip) continue;

        NestedCand c;
        c.va = fn.first;
        c.size = fn.second;
        c.directCalls = ri.direct;
        c.closure = seen.size();
        c.ptr_mask = ri.ptrMask;
        if (out) *out = c;
        if (closure) {
            closure->clear();
            for (uint64_t v : seen)
                for (const auto& f : pe.functions) if (f.first == v) { closure->push_back(f); break; }
            std::sort(closure->begin(), closure->end());
        }
        std::fprintf(stderr, "[nested] picked va=0x%llx direct=%d closure=%zu\n",
                     (unsigned long long)c.va, c.directCalls, c.closure);
        return true;
    }
    }
    std::fprintf(stderr, "[nested] none. scanned=%zu ok+rip=%zu direct-range=%zu\n",
                 nRoot, nRip, nDirect);
    for (const auto& n : nears)
        std::fprintf(stderr, "[nested] near va=0x%llx direct=%d closure=%zu stubbed=%zu iat=%d ind=%d\n",
                     (unsigned long long)n.va, n.direct, n.closure, n.stubbed,
                     (int)n.iat, (int)n.ind);
    return false;
}

void emitShardSet(const PeImage& pe, int shards, const std::string& outDir,
                  const std::vector<std::pair<uint64_t, uint32_t>>* only,
                  ShardStats* stats) {
    std::vector<std::pair<uint64_t, uint32_t>> list =
        only ? *only : pe.functions;
    std::sort(list.begin(), list.end());
    if (shards < 1) shards = 1;

    std::vector<std::vector<std::pair<uint64_t, uint32_t>>> buckets((size_t)shards);
    for (size_t i = 0; i < list.size(); ++i)
        buckets[i * (size_t)shards / list.size()].push_back(list[i]);

    ShardStats st;
    st.total = list.size();
    st.shards = (size_t)shards;

    // all_decls.h：所有函数声明 + 垫片声明
    {
        std::ofstream o(outDir + "/all_decls.h");
        o << "#pragma once\n#include <cstdint>\n#include <cstdio>\n#include <cstdlib>\n"
             "#include \"x64_runtime.h\"\n#include \"x64_ops.h\"\n\n";
        for (const auto& fn : list)
            o << "void sub_" << hexva(fn.first) << "(X64Ctx* ctx);\n";
        o << "\n// IAT 垫片\n";
        for (const auto& im : pe.imports)
            o << "void shim_" << im.dll << "_" << im.name << "(X64Ctx* ctx);\n";
    }

    // 分片
    for (int si = 0; si < shards; ++si) {
        std::ostringstream name;
        name << outDir << "/shard_" << (si < 10 ? "00" : si < 100 ? "0" : "") << si << ".cpp";
        std::ofstream o(name.str());
        o << "// shard " << si << " / " << shards << "  functions=" << buckets[(size_t)si].size() << "\n"
             "#include \"all_decls.h\"\n\n";
        for (const auto& fn : buckets[(size_t)si]) {
            LiftResult r = liftFunctionEx(pe, fn.first, fn.second,
                                          LIFT_ALLOW_CALL | LIFT_TAIL_JUMP | LIFT_STUB_UNKNOWN);
            if (r.ok) {
                o << "// va=0x" << hexva(fn.first) << " size=" << fn.second
                  << " insns=" << r.insnCount << (r.stubbed ? " STUBBED" : "") << "\n";
                o << r.code << "\n";
                if (r.stubbed) ++st.stubbed; else ++st.ok;
            } else {
                o << "// va=0x" << hexva(fn.first) << " LIFT-FAILED:";
                for (const auto& u : r.unsupported) o << " " << u;
                o << "\nvoid sub_" << hexva(fn.first) << "(X64Ctx* ctx) {\n"
                     "  UNIMPL_FUNC(0x" << hexva(fn.first) << "ULL);\n}\n\n";
                ++st.failed;
                std::string reason = r.unsupported.empty() ? "unknown" : r.unsupported[0];
                st.failReasons[reason]++;
            }
        }
    }

    // dispatch_table.cpp
    {
        std::ofstream o(outDir + "/dispatch_table.cpp");
        o << "// 间接调用分发表（55,712 项，二分查找友好）\n#include \"all_decls.h\"\n\n";
        o << "struct DispatchEntry { uint64_t va; RecompFn fn; };\n";
        o << "static const DispatchEntry kDispatch[] = {\n";
        for (const auto& fn : list)
            o << "  {0x" << hexva(fn.first) << "ULL, sub_" << hexva(fn.first) << "},\n";
        o << "};\n\n";
        o << "void init_dispatch_table(const char* extra_url, void* extra) {\n"
             "  (void)extra_url; (void)extra;\n"
             "  for (const auto& e : kDispatch) register_recomp_fn(e.va, e.fn);\n"
             "}\n";
    }

    // 所有 IAT 入口的弱定义占位（手写垫片覆盖它）
    {
        std::ofstream o(outDir + "/shims_auto.cpp");
        o << "// 自动生成的 IAT 占位（weak，手写垫片优先）\n#include \"all_decls.h\"\n\n";
        for (const auto& im : pe.imports) {
            o << "__attribute__((weak)) void shim_" << im.dll << "_" << im.name
              << "(X64Ctx* ctx) {\n  UNIMPL_API(\"" << im.dll << "!" << im.name << "\");\n}\n";
        }
    }

    // 清单
    {
        std::ofstream o(outDir + "/manifest.tsv");
        o << "va\tsize\tshard\n";
        for (int si = 0; si < shards; ++si)
            for (const auto& fn : buckets[(size_t)si])
                o << "0x" << hexva(fn.first) << "\t" << fn.second << "\t" << si << "\n";
    }

    if (!st.failReasons.empty()) {
        std::fprintf(stderr, "[fail] reasons:");
        for (const auto& kv : st.failReasons)
            std::fprintf(stderr, " %s=%zu", kv.first.c_str(), kv.second);
        std::fprintf(stderr, "\n");
    }
    if (stats) *stats = st;
    std::fprintf(stderr, "[shards] total=%zu ok=%zu stubbed=%zu failed=%zu shards=%zu imports=%zu\n",
                 st.total, st.ok, st.stubbed, st.failed, st.shards, pe.imports.size());
}
