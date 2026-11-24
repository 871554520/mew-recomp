#include "lifter_core.h"

#include <Zydis/Zydis.h>
#include <cstdio>
#include <cstring>
#include <sstream>

// ---------------- PE ----------------
const Section* PeImage::byRva(uint32_t rva) const {
    for (const auto& s : sections)
        if (rva >= s.va && rva < s.va + std::max(s.vsize, s.rawsize)) return &s;
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
};

std::string addrExpr(const PeImage& pe, const ZydisDecodedOperand& op, uint64_t next_rip, Emit& e) {
    if (op.mem.base == ZYDIS_REGISTER_RIP) {
        int64_t d = op.mem.disp.has_displacement ? (int64_t)op.mem.disp.value : 0;
        e.usesRipData = true;
        return std::to_string((unsigned long long)(next_rip + d)) + "ULL /*rip*/";
    }
    if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE) {
        // 绝对地址访问（镜像内全局/字符串）——阶段 2 排除
        e.usesNonStackMem = true;
    }
    if (op.mem.base != ZYDIS_REGISTER_NONE &&
        op.mem.base != ZYDIS_REGISTER_RSP && op.mem.base != ZYDIS_REGISTER_RBP) {
        e.usesNonStackMem = true;
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

void storeExpr(const PeImage& pe, const ZydisDecodedInstruction& in, const ZydisDecodedOperand& dst,
               const std::string& val, uint64_t next_rip, int bytes, Emit& e) {
    (void)in;
    if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int id = gprId(dst.reg.value);
        if (id >= 0) { e.out << "  write_reg(ctx," << id << "," << val << "," << bytes << ");\n"; return; }
        int xi = xmmId(dst.reg.value);
        if (xi >= 0) { e.out << "  xmm_set_u64(ctx," << xi << "," << val << ");\n"; return; }
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

std::string ccExpr(const std::string& mn) {
    if (mn == "jz" || mn == "je") return "ctx->zf";
    if (mn == "jnz" || mn == "jne") return "!ctx->zf";
    if (mn == "js") return "ctx->sf";
    if (mn == "jns") return "!ctx->sf";
    if (mn == "jc" || mn == "jb") return "ctx->cf";
    if (mn == "jnc" || mn == "jae") return "!ctx->cf";
    if (mn == "jbe") return "(ctx->cf || ctx->zf)";
    if (mn == "ja") return "(!ctx->cf && !ctx->zf)";
    if (mn == "jl") return "(ctx->sf != ctx->of)";
    if (mn == "jge") return "(ctx->sf == ctx->of)";
    if (mn == "jle") return "(ctx->zf || (ctx->sf != ctx->of))";
    if (mn == "jg") return "(!ctx->zf && (ctx->sf == ctx->of))";
    return "";
}

// setcc / cmovcc 后缀 → 条件表达式
std::string ccSuffix(const std::string& mn, const char* prefix) {
    size_t n = std::strlen(prefix);
    if (mn.rfind(prefix, 0) != 0) return "";
    std::string suf = mn.substr(n);
    if (suf == "z" || suf == "e") return "ctx->zf";
    if (suf == "nz" || suf == "ne") return "!ctx->zf";
    if (suf == "s") return "ctx->sf";
    if (suf == "ns") return "!ctx->sf";
    if (suf == "c" || suf == "b") return "ctx->cf";
    if (suf == "nc" || suf == "ae") return "!ctx->cf";
    if (suf == "be") return "(ctx->cf || ctx->zf)";
    if (suf == "a") return "(!ctx->cf && !ctx->zf)";
    if (suf == "l") return "(ctx->sf != ctx->of)";
    if (suf == "ge") return "(ctx->sf == ctx->of)";
    if (suf == "le") return "(ctx->zf || (ctx->sf != ctx->of))";
    if (suf == "g") return "(!ctx->zf && (ctx->sf == ctx->of))";
    return "";
}

}  // namespace

LiftResult liftFunction(const PeImage& pe, uint64_t va, uint32_t size) {
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

    Emit e;
    e.out << "void sub_" << std::hex << va << std::dec << "(X64Ctx* ctx) {\n";

    size_t off = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    while (off < effSize) {
        uint64_t rip = va + off;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + off, effSize - off, &insn, ops))) {
            e.unsupported.push_back("decode-fail");
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
                if (t < va || t >= va + effSize) { e.unsupported.push_back("jump-out-of-func"); break; }
                e.out << "  goto L_" << std::hex << t << std::dec << ";\n";
            } else {
                e.unsupported.push_back("jmp-indirect");
            }
        } else if (isJcc) {
            uint64_t t = next_rip + (int64_t)ops[0].imm.value.s;
            if (t < va || t >= va + effSize) { e.unsupported.push_back("jump-out-of-func"); break; }
            std::string cond = ccExpr(mn);
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
            e.unsupported.push_back("call");
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
    return res;
}

bool pickPureFunction(const PeImage& pe, size_t minSize, size_t maxSize,
                      std::vector<std::pair<uint64_t, uint32_t>>& out) {
    out.clear();
    size_t nSize = 0, nLift = 0, nNoCall = 0, nNoRip = 0, nNoAbs = 0, nTerm = 0;
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
        if (r.usesNonStackMem) continue;
        ++nNoAbs;
        if (r.usesMemory && !r.hasPrologue) continue;
        if (r.fallsOffEnd) {
            fprintf(stderr, "[fell-off] va=0x%llx size=%u insns=%d last=%s\n",
                    (unsigned long long)fn.first, fn.second, r.insnCount, r.lastMnemonic.c_str());
            continue;
        }
        ++nTerm;
        if (out.size() < 8) out.push_back(fn);
    }
    fprintf(stderr, "[funnel] size=%zu lift_ok=%zu no_call=%zu no_ripdata=%zu no_absmem=%zu terminated=%zu\n",
            nSize, nLift, nNoCall, nNoRip, nNoAbs, nTerm);
    return !out.empty();
}
