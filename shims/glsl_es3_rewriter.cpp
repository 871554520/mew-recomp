#include "glsl_es3_rewriter.h"

#include <cstdint>
#include <cstdio>
#include <regex>

namespace {

// 只在“独立单词”层面替换，避免把 my_attribute 之类误改
std::string replace_word(const std::string& in, const std::string& from, const std::string& to) {
    std::regex re("\\b" + from + "\\b");
    return std::regex_replace(in, re, to);
}

}  // namespace

std::string glsl_hash8(const std::string& src) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : src) { h ^= c; h *= 1099511628211ULL; }
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return std::string(buf);
}

std::string rewrite_glsl_to_es3(const std::string& src, bool is_fragment) {
    std::string out = src;

    // 1) 统一 #version（桌面 110/120/330/450 都压成 300 es）
    bool had_version = false;
    {
        std::regex ver(R"(#version[ \t]+([0-9]+)[^\n]*)");
        if (std::regex_search(out, ver)) had_version = true;
        out = std::regex_replace(out, ver, "#version 300 es");
    }

    // 2) 去掉 ES3 不接受的兼容性/扩展声明（例如 #extension GL_ARB_* : enable）
    out = std::regex_replace(out, std::regex(R"(#extension[^\n]*ARB[^\n]*)"), "");

    // 3) 片元：补 precision，gl_FragColor → out 变量
    if (is_fragment) {
        bool has_precision = out.find("precision highp float;") != std::string::npos;
        std::string header;
        if (!has_precision) header += "precision highp float;\nprecision highp int;\n";
        if (out.find("gl_FragColor") != std::string::npos) {
            header += "out vec4 mew_frag_color;\n";
            out = replace_word(out, "gl_FragColor", "mew_frag_color");
        }
        // 插到 #version 行之后（没有 version 就插到最前）
        size_t pos = out.find('\n');
        if (pos == std::string::npos) pos = out.size();
        if (had_version) out.insert(pos + 1, header);
        else out = "#version 300 es\n" + header + out;
    } else {
        if (!had_version) out = "#version 300 es\n" + out;
    }

    // 4) 顶点/片元共有的旧关键字
    out = replace_word(out, "attribute", "in");
    out = replace_word(out, "varying", is_fragment ? "in" : "out");

    // 5) 废弃采样函数与内置纹理函数
    std::regex tex2d(R"(\btexture2D\s*\()");
    out = std::regex_replace(out, tex2d, "texture(");
    std::regex tex2dproj(R"(\btexture2DProj\s*\()");
    out = std::regex_replace(out, tex2dproj, "textureProj(");

    // 6) gl_FragData[0] → mew_frag_color
    if (is_fragment) {
        std::regex fragdata(R"(\bgl_FragData\s*\[\s*0\s*\])");
        out = std::regex_replace(out, fragdata, "mew_frag_color");
    }

    return out;
}
