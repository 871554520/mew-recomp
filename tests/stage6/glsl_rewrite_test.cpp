// 阶段 6：GLSL → GLES 3.00 改写器的回归测试（纯字符串，可在 Ubuntu CI 跑）
#include <cstdio>
#include <string>

#include "glsl_es3_rewriter.h"

static int g_pass = 0, g_fail = 0;

static void expect_contains(const char* name, const std::string& hay, const std::string& needle) {
    if (hay.find(needle) != std::string::npos) { ++g_pass; }
    else {
        ++g_fail;
        std::printf("FAIL %s: missing \"%s\"\n--- output ---\n%s\n", name, needle.c_str(), hay.c_str());
    }
}
static void expect_absent(const char* name, const std::string& hay, const std::string& needle) {
    if (hay.find(needle) == std::string::npos) { ++g_pass; }
    else {
        ++g_fail;
        std::printf("FAIL %s: still has \"%s\"\n--- output ---\n%s\n", name, needle.c_str(), hay.c_str());
    }
}

int main() {
    const std::string vs_120 =
        "#version 120\n"
        "attribute vec3 a_pos;\n"
        "attribute vec2 a_uv;\n"
        "varying vec2 v_uv;\n"
        "void main() { v_uv = a_uv; gl_Position = vec4(a_pos, 1.0); }\n";
    std::string vs = rewrite_glsl_to_es3(vs_120, false);
    expect_contains("vs version", vs, "#version 300 es");
    expect_contains("vs attribute->in", vs, "in vec3 a_pos;");
    expect_contains("vs varying->out", vs, "out vec2 v_uv;");
    expect_absent("vs no attribute", vs, "attribute");

    const std::string fs_120 =
        "#version 120\n"
        "varying vec2 v_uv;\n"
        "uniform sampler2D u_tex;\n"
        "void main() { gl_FragColor = texture2D(u_tex, v_uv); }\n";
    std::string fs = rewrite_glsl_to_es3(fs_120, true);
    expect_contains("fs version", fs, "#version 300 es");
    expect_contains("fs precision", fs, "precision highp float;");
    expect_contains("fs out decl", fs, "out vec4 mew_frag_color;");
    expect_contains("fs texture()", fs, "texture(u_tex, v_uv)");
    expect_absent("fs no gl_FragColor", fs, "gl_FragColor");
    expect_absent("fs no texture2D", fs, "texture2D(");
    expect_contains("fs varying->in", fs, "in vec2 v_uv;");

    // 没有 #version 的裸源码：要自动补头
    const std::string bare = "void main() { gl_FragColor = vec4(1.0); }\n";
    std::string fb = rewrite_glsl_to_es3(bare, true);
    expect_contains("bare version", fb, "#version 300 es");
    expect_contains("bare out", fb, "mew_frag_color");

    // 幂等性：对已改写过的源码再跑一次，不应再加一层 #version
    std::string again = rewrite_glsl_to_es3(fs, true);
    size_t first = again.find("#version 300 es");
    size_t second = again.find("#version 300 es", first + 1);
    if (second == std::string::npos) ++g_pass;
    else { ++g_fail; std::printf("FAIL idempotent: duplicated #version\n%s\n", again.c_str()); }

    std::printf("GLSL_REWRITE pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
