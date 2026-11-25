// 阶段 3 门禁 3：链接探针（证明 libmew_recomp.a 中的函数体与分发表可链接）
#include <cstdio>
#include "x64_runtime.h"

// 任意一个真实函数由 CI 用 -D 传入，例如 -DPROBE_SYM=sub_140001000
void PROBE_SYM(X64Ctx* ctx);

int main() {
    init_dispatch_table();
    X64Ctx ctx{};
    std::printf("link probe ok sym=%p\n", (void*)&PROBE_SYM);
    return 0;
}
