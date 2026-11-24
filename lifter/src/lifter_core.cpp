#include "lifter_core.h"

#include <Zydis/Zydis.h>
#include <cstdio>
#include <cstring>
#include <sstream>

const Section* PeImage::byRva(uint32_t rva) const {
    for (const auto& s : sections)
        if (rva >= s.va && rva < s.va + s.vsize) return &s;
    return nullptr;
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
    // .pdata 函数表
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

namespace {

struct Emit {
    std::ostringstream out;
    std::vector<std::string> unsupported;
    int count = 0;
    bool usesRipData = false;
    bool hasCall = false;
    bool usesMemory = false;
    bool writesMemory = false;
    bool hasPrologue = false;
};

int regIdOf(ZydisRegister r) {
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

std::string memExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& op,
                    uint64_t next_rip, Emit& e) {
    if (op.mem.base == ZYDIS_REGISTER_RIP) {
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        uint64_t abs = next_rip + d;
        e.usesRipData = true;
        return std::to_string(abs) + "ULL /* rip-data */";
    }
    std::ostringstream s;
    bool any = false;
    if (op.mem.base != ZYDIS_REGISTER_NONE) {
        int b = regIdOf(op.mem.base);
        if (b < 0) return "/*bad base*/0";
        s << "read_reg(ctx," << b << ",8)";
        any = true;
    }
    if (op.mem.index != ZYDIS_REGISTER_NONE) {
        int i = regIdOf(op.mem.index);
        if (i < 0) return "/*bad index*/0";
        s << " + read_reg(ctx," << i << ",8)*" << (int)op.mem.scale;
        any = true;
    }
    {
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        if (d || !any) {
            if (any) s << " + ";
            s << "(" << d << "LL)";
            any = true;
        }
    }
    (void)in;
    return s.str();
}

std::string srcExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& op,
                    uint64_t next_rip, Emit& e) {
    switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER: {
            int id = regIdOf(op.reg.value);
            if (id < 0) { e.unsupported.push_back("reg"); return "0"; }
            return "read_reg(ctx," + std::to_string(id) + "," + std::to_string(op.size / 8) + ")";
        }
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            return std::to_string((uint64_t)op.imm.value.u) + "ULL";
        case ZYDIS_OPERAND_TYPE_MEMORY:
            return "mem_read<uint64_t>(ctx," + memExpr(pe, in, op, next_rip, e) + ")";
        default:
            return "0";
    }
}

void emitStore(const ZydisDecodedInstruction& in, const ZydisDecodedOperand& dst, const std::string& val, Emit& e) {
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int id = regIdOf(dst.reg.value);
        int w = dst.size / 8;
        e.out << "  write_reg(ctx," << id << "," << val << "," << w << ");\n";
    } else if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        e.out << "  mem_write<uint64_t>(ctx," << /* addr computed by caller */ "0" << "," << val << ");\n";
    }
    (void)in;
}

}  // namespace

LiftResult liftFunction(const PeImage& pe, uint64_t va, uint32_t size) {
    LiftResult res;
    const Section* sec = pe.byRva((uint32_t)(va - pe.image_base));
    if (!sec) { res.unsupported.push_back("no section"); return res; }
    const uint8_t* code = pe.data.data() + sec->raw + (uint32_t)(va - pe.image_base - sec->va);

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    Emit e;
    e.out << "void sub_" << std::hex << va << std::dec << "(X64Ctx* ctx) {\n";
    size_t off = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    while (off < size) {
        uint64_t rip = va + off;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, size - off, &insn, ops))) {
            e.unsupported.push_back("decode-fail");
            break;
        }
        uint64_t next_rip = rip + insn.length;
        if (e.count == 0) {
            // 首条：push/sumb rsp 或 mov [rsp],reg 视为标准序言（函数自己会建立栈帧）
            if (mn == "push" || (mn == "sub" && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                 ops[0].reg.value == ZYDIS_REGISTER_RSP) ||
                mn == "mov" && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.hasPrologue = true;
            }
        }
        for (int oi = 0; oi < insn.operand_count; ++oi) {
            if (ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.usesMemory = true;
                if (oi == 0) e.writesMemory = true;
            }
        }
        e.out << "L_" << std::hex << rip << std::dec << ": ;\n";
        const char* m = ZydisMnemonicGetString(insn.mnemonic);
        std::string mn = m ? m : "?";
        e.count++;

        if (mn == "nop" || mn == "int3" || mn == "endbr64") {
            // no-op
        } else if (mn == "ret") {
            e.out << "  ctx->rsp += 8; return;\n";
        } else if (mn == "push") {
            e.out << "  ctx->rsp -= 8; mem_write<uint64_t>(ctx, ctx->rsp, " << srcExpr(pe, insn, ops[0], next_rip, e) << ");\n";
        } else if (mn == "pop") {
            int id = regIdOf(ops[0].reg.value);
            e.out << "  write_reg(ctx," << id << ",mem_read<uint64_t>(ctx,ctx->rsp),8); ctx->rsp += 8;\n";
        } else if (mn == "mov" || mn == "movzx" || mn == "movsx" || mn == "movsxd") {
            std::string v = srcExpr(pe, insn, ops[1], next_rip, e);
            if (mn == "movzx") {
                unsigned bits = ops[1].size;
                if (bits < 64) {
                    std::ostringstream t;
                    t << std::hex << ((1ULL << bits) - 1);
                    v = "(" + v + " & 0x" + t.str() + "ULL)";
                }
            }
            if (mn == "movsx" || mn == "movsxd") v = "(uint64_t)(int64_t)(int" + std::to_string(ops[1].size * 8) + "_t)(" + v + ")";
            if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.out << "  mem_write<uint64_t>(ctx," << memExpr(pe, insn, ops[0], next_rip, e) << "," << v << ");\n";
            } else {
                int id = regIdOf(ops[0].reg.value);
                e.out << "  write_reg(ctx," << id << "," << v << "," << ops[0].size / 8 << ");\n";
            }
        } else if (mn == "lea") {
            int id = regIdOf(ops[0].reg.value);
            e.out << "  write_reg(ctx," << id << "," << memExpr(pe, insn, ops[1], next_rip, e) << "," << ops[0].size / 8 << ");\n";
        } else if (mn == "add" || mn == "sub" || mn == "cmp" || mn == "and" || mn == "or" || mn == "xor" || mn == "test") {
            std::string a = srcExpr(pe, insn, ops[0], next_rip, e);
            std::string b = srcExpr(pe, insn, ops[1], next_rip, e);
            int w = ops[0].size / 8;
            std::string fn = (mn == "add") ? "add_flags" : (mn == "sub" || mn == "cmp") ? "sub_flags" : "logic_flags";
            std::string expr = (mn == "and") ? "(" + a + " & " + b + ")" :
                               (mn == "or") ? "(" + a + " | " + b + ")" :
                               (mn == "xor") ? "(" + a + " ^ " + b + ")" :
                               (mn == "test") ? "(" + a + " & " + b + ")" : "";
            std::string call;
            if (fn == "logic_flags") call = "logic_flags(ctx," + expr + "," + std::to_string(w) + ")";
            else call = fn + "(ctx," + a + "," + b + "," + std::to_string(w) + ")";
            if (mn == "cmp" || mn == "test") {
                e.out << "  " << call << ";\n";
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                e.out << "  mem_write<uint64_t>(ctx," << memExpr(pe, insn, ops[0], next_rip, e) << "," << call << ");\n";
            } else {
                int id = regIdOf(ops[0].reg.value);
                e.out << "  write_reg(ctx," << id << "," << call << "," << w << ");\n";
            }
        } else if (mn == "jmp") {
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
                if (t < va || t >= va + size) { e.unsupported.push_back("jump-out-of-func"); break; }
                e.out << "  goto L_" << std::hex << t << std::dec << ";\n";
            } else {
                e.unsupported.push_back("jmp-indirect");
            }
        } else if (mn.rfind("j", 0) == 0) {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            if (t < va || t >= va + size) { e.unsupported.push_back("jump-out-of-func"); break; }
            std::string cond;
            if (mn == "jz" || mn == "je") cond = "ctx->zf";
            else if (mn == "jnz" || mn == "jne") cond = "!ctx->zf";
            else if (mn == "js") cond = "ctx->sf";
            else if (mn == "jns") cond = "!ctx->sf";
            else if (mn == "jc" || mn == "jb") cond = "ctx->cf";
            else if (mn == "jnc" || mn == "jae") cond = "!ctx->cf";
            else if (mn == "jbe") cond = "(ctx->cf || ctx->zf)";
            else if (mn == "ja") cond = "(!ctx->cf && !ctx->zf)";
            else if (mn == "jl") cond = "(ctx->sf != ctx->of)";
            else if (mn == "jge") cond = "(ctx->sf == ctx->of)";
            else if (mn == "jle") cond = "(ctx->zf || (ctx->sf != ctx->of))";
            else if (mn == "jg") cond = "(!ctx->zf && (ctx->sf == ctx->of))";
            else cond = "";
            if (cond.empty()) e.unsupported.push_back(mn);
            else e.out << "  if (" << cond << ") goto L_" << std::hex << t << std::dec << ";\n";
        } else if (mn == "call") {
            e.hasCall = true;
            e.unsupported.push_back("call");
        } else if (mn == "shl" || mn == "shr" || mn == "sar") {
            std::string a = srcExpr(pe, insn, ops[0], next_rip, e);
            std::string b = srcExpr(pe, insn, ops[1], next_rip, e);
            int w = ops[0].size / 8;
            std::string op2 = (mn == "shl") ? "<<" : (mn == "shr") ? ">>" : ">>";
            if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                int id = regIdOf(ops[0].reg.value);
                e.out << "  write_reg(ctx," << id << ",(" << a << " " << op2 << " (" << b << " & 63))," << w << ");\n";
            } else {
                e.unsupported.push_back(mn + "-mem");
            }
        } else {
            e.unsupported.push_back(mn);
        }

        off += insn.length;
        if (!e.unsupported.empty()) break;
    }
    e.out << "}\n";
    res.ok = e.unsupported.empty() && e.count > 0;
    res.code = e.out.str();
    res.unsupported = e.unsupported;
    res.insnCount = e.count;
    res.usesRipData = e.usesRipData;
    res.hasCall = e.hasCall;
    res.usesMemory = e.usesMemory;
    res.writesMemory = e.writesMemory;
    res.hasPrologue = e.hasPrologue;
    return res;
}

bool pickPureFunction(const PeImage& pe, size_t minSize, size_t maxSize,
                      std::vector<std::pair<uint64_t, uint32_t>>& out) {
    out.clear();
    for (const auto& fn : pe.functions) {
        if (fn.second < minSize || fn.second > maxSize) continue;
        LiftResult r = liftFunction(pe, fn.first, fn.second);
        if (!r.ok || r.usesRipData || r.hasCall) continue;
        // 阶段 2 只验：无 call、无 RIP 数据、跳转不出界、且要么纯寄存器要么有标准序言
        if (r.usesMemory && !r.hasPrologue) continue;
        out.push_back(fn);
        if (out.size() >= 8) break;
    }
    return !out.empty();
}
