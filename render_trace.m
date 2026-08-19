// render_trace.m — 候选 setter 调用点追踪 dylib (v3)
// 目的: 定位 render-scale 站点1/站点2 的精确文件偏移。
//
// 原理:
//   Starling 对象 scaleX@0x50 / scaleY@0x54 (float)。AOT 赋值编译为微型 setter:
//     STR W<x>, [X0, #imm]; RET
//   本 dylib 把 setter 第 1 条指令改为  B <trampoline>  (4字节, 不破坏相邻),
//   trampoline(mmapped 在 ±128MB 内): 记录(调用点=lr, this=x0, 值=源寄存器)
//   -> 执行原 STR -> RET。
//   日志写入 Documents/render_trace.log + stderr。
//
// 编译 (macOS 交叉编译, 同 render_scan.m):
//   SDK=$(xcrun --sdk iphoneos --show-sdk-path)
//   clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 -fobjc-arc -dynamiclib \
//     -framework UIKit -framework Foundation \
//     -o RenderTrace.dylib render_trace.m
//   ldid -S RenderTrace.dylib
//
// 注入: 与 render_scan.m 相同 — dylib 放 Frameworks/ + 主二进制加 LC_LOAD_DYLIB。
//
// 使用: 注入安装 -> 打开角色页/编队/主城 -> 进一次战斗 ->
//       读 Documents/render_trace.log, 值=6.0(0x40c00000)/1.0(0x3f800000) 的调用点即目标。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libkern/OSCacheControl.h>
#import <stdio.h>
#import <string.h>
#import <stdarg.h>
#import <stdlib.h>
#import <unistd.h>
#import <sys/mman.h>

#define MAX_CALLS 512
#define MAX_SETTERS 16
#define MAX_LOG 131072

// ---------------- 候选 setter (文件偏移, 来自 IDA) ----------------
typedef struct {
    const char *name;
    uint64_t file_off;   // 文件偏移 = vaddr - 0x100000000
    uint32_t field_imm;  // 写字段偏移
} setter_cfg_t;

static const setter_cfg_t SETTERS[] = {
    { "sX_50_a", 0xb8cc,   0x50 },   // STR W2,[X0,#0x50]  scaleX 候选
    { "sY_54_a", 0x1ca6cc, 0x54 },   // STR W1,[X0,#0x54]  scaleY 候选
    { "sX_50_b", 0x1788f4, 0x50 },   // STR W8,[X0,#0x50]
    { "sY_54_b", 0x3df8b0, 0x54 },   // STR W8,[X0,#0x54]
    { "sX_50_d", 0x3a812c, 0x50 },   // STR W8,[X0,#0x50]
};
#define NSETTERS (sizeof(SETTERS)/sizeof(SETTERS[0]))

// ---------------- 日志 ----------------
static char g_log[MAX_LOG];
static int g_len = 0;

static void TLog(const char *fmt, ...) {
    if (g_len >= MAX_LOG - 400) return;
    va_list ap;
    va_start(ap, fmt);
    g_len += vsnprintf(g_log + g_len, MAX_LOG - g_len, fmt, ap);
    va_end(ap);
}

uint64_t g_slide = 0;

// ---------------- 调用记录 (去重) ----------------
typedef struct { uint64_t call; uint32_t val; int count; } call_entry_t;
static call_entry_t g_calls[MAX_SETTERS][MAX_CALLS];
static int g_call_n[MAX_SETTERS];

__attribute__((noinline))
static void record_call(int idx, uint64_t call_vaddr, uint64_t this_ptr, uint32_t val) {
    if (idx < 0 || idx >= NSETTERS) return;
    uint64_t file_off = call_vaddr - g_slide - 0x100000000ULL;
    float f; memcpy(&f, &val, 4);
    TLog("[RT] %s file=0x%llx val=0x%08x (%.2f) this=%llx\n",
         SETTERS[idx].name, file_off, val, f, this_ptr);
    call_entry_t *arr = g_calls[idx];
    for (int i = 0; i < g_call_n[idx]; i++) {
        if (arr[i].call == file_off) { arr[i].val = val; arr[i].count++; return; }
    }
    if (g_call_n[idx] < MAX_CALLS) {
        arr[g_call_n[idx]].call = file_off;
        arr[g_call_n[idx]].val = val;
        arr[g_call_n[idx]].count = 1;
        g_call_n[idx]++;
    }
}

// 每 setter 一个 logger 包装 (trampoline 加载其地址, 参数 x0=call, x1=this, x2=val)
#define MAKE_LOGGER(n) \
    __attribute__((noinline)) static void logger_##n(uint64_t c, uint64_t t, uint32_t v) { \
        record_call(n, c, t, v); \
    }
MAKE_LOGGER(0) MAKE_LOGGER(1) MAKE_LOGGER(2) MAKE_LOGGER(3) MAKE_LOGGER(4)
MAKE_LOGGER(5) MAKE_LOGGER(6) MAKE_LOGGER(7) MAKE_LOGGER(8) MAKE_LOGGER(9)

static uint64_t logger_addr(int n) {
    switch (n) {
        case 0: return (uint64_t)(uintptr_t)&logger_0;
        case 1: return (uint64_t)(uintptr_t)&logger_1;
        case 2: return (uint64_t)(uintptr_t)&logger_2;
        case 3: return (uint64_t)(uintptr_t)&logger_3;
        case 4: return (uint64_t)(uintptr_t)&logger_4;
        case 5: return (uint64_t)(uintptr_t)&logger_5;
        case 6: return (uint64_t)(uintptr_t)&logger_6;
        case 7: return (uint64_t)(uintptr_t)&logger_7;
        case 8: return (uint64_t)(uintptr_t)&logger_8;
        default: return (uint64_t)(uintptr_t)&logger_9;
    }
}

// ---------------- 指令生成 ----------------
static void emit32(uint32_t **p, uint32_t w) { **p = w; (*p)++; }

// 构造 trampoline (写入 mem, RWX): 记录调用 -> 执行原 STR W<rt>,[X0,#imm] -> RET
static void build_trampoline(uint8_t *mem, uint32_t rt, uint32_t imm, uint64_t lg) {
    uint32_t *p = (uint32_t *)mem;
    emit32(&p, 0xA9BF7BE0);                          // stp x0, x30, [sp, #-16]!
    emit32(&p, 0xA9BF0BE1);                          // stp x1, x2, [sp, #-16]!
    emit32(&p, 0xF9400FE0);                          // ldr x0, [sp, #24]   call=lr
    emit32(&p, 0xF9400BE1);                          // ldr x1, [sp, #16]   this
    emit32(&p, 0x2A0003E2 | (rt << 16));             // mov w2, w<rt>       val
    uint64_t laddr = lg;
    emit32(&p, 0xD2800000 | ((uint32_t)(laddr & 0xFFFF) << 5) | 16);          // movz x16,#lo
    emit32(&p, 0xF2A00000 | ((uint32_t)((laddr >> 16) & 0xFFFF) << 5) | 16);  // movk x16,#..,lsl16
    emit32(&p, 0xF2C00000 | ((uint32_t)((laddr >> 32) & 0xFFFF) << 5) | 16);  // movk x16,#..,lsl32
    emit32(&p, 0xF2E00000 | ((uint32_t)((laddr >> 48) & 0xFFFF) << 5) | 16);  // movk x16,#..,lsl48
    emit32(&p, 0xD63F0200);                          // blr x16
    emit32(&p, 0xA8C10BE1);                          // ldp x1, x2, [sp], #16
    emit32(&p, 0xA8C17BE0);                          // ldp x0, x30, [sp], #16
    emit32(&p, 0xB9000000 | (rt << 0) | ((imm / 4) << 10));                  // str w<rt>,[x0,#imm]
    emit32(&p, 0xD65F03C0);                          // ret
    sys_icache_invalidate(mem, (uint8_t *)p - mem);
}

// 在 target ±128MB 内分配可执行内存
static uint8_t *mmap_near(uint64_t target, size_t size) {
    uint64_t page_lo = target & ~0xFFFFFULL;
    for (int attempt = 0; attempt < 256; attempt++) {
        uint8_t *hint = (uint8_t *)(page_lo + attempt * 0x10000);
        uint8_t *m = mmap(hint, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANON | MAP_PRIVATE, -1, 0);
        if (m == MAP_FAILED) continue;
        int64_t diff = (int64_t)((uint64_t)m - target);
        if (diff > -0x8000000LL && diff < 0x8000000LL) return m;
        munmap(m, size);
    }
    return NULL;
}

// hook 一个 setter: 入口 1 条指令改 B <trampoline>
static int hook_setter(int idx, uint64_t slide) {
    const setter_cfg_t *sc = &SETTERS[idx];
    uint8_t *runtime = (uint8_t *)(slide + 0x100000000ULL + sc->file_off);

    uint32_t orig = *(uint32_t *)runtime;
    if ((orig & 0xFFC00000) != 0xB9000000) {
        TLog("[RT] %s 0x%llx 不是 STR W (0x%08x), 跳过\n", sc->name, sc->file_off, orig);
        return 0;
    }
    uint32_t rt = orig & 0x1F;
    uint32_t rn = (orig >> 5) & 0x1F;
    if (rn != 0) {
        TLog("[RT] %s 0x%llx 基址寄存器 X%d != X0, 跳过\n", sc->name, sc->file_off, rn);
        return 0;
    }
    uint32_t nxt = *(uint32_t *)(runtime + 4);
    if (nxt != 0xD65F03C0) {
        TLog("[RT] %s 0x%llx S+4 不是 RET, 跳过\n", sc->name, sc->file_off);
        return 0;
    }

    uint8_t *tramp = mmap_near((uint64_t)runtime, 0x4000);
    if (!tramp) { TLog("[RT] %s mmap_near FAIL\n", sc->name); return 0; }
    build_trampoline(tramp, rt, sc->field_imm, logger_addr(idx));

    int64_t b_off = (int64_t)(tramp - (runtime + 4));
    if (b_off / 4 < -0x2000000 || b_off / 4 >= 0x2000000) {
        TLog("[RT] %s trampoline 超出 B 范围, 跳过\n", sc->name);
        return 0;
    }
    uint32_t b_instr = 0x14000000 | ((uint32_t)(b_off / 4) & 0x3FFFFFF);

    uintptr_t page = (uintptr_t)runtime & ~0xFFFULL;
    if (mprotect((void *)page, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        TLog("[RT] %s mprotect FAIL\n", sc->name);
        return 0;
    }
    *(uint32_t *)runtime = b_instr;
    sys_icache_invalidate(runtime, 4);
    TLog("[RT] hooked %s @0x%llx (rt=w%d imm=0x%x) tramp=%p b_off=%lld\n",
         sc->name, sc->file_off, rt, sc->field_imm, tramp, (long long)b_off);
    return 1;
}

// ---------------- 构造器 ----------------
__attribute__((constructor))
static void init(void) {
    TLog("[RT] render trace dylib v3 loaded pid=%d\n", getpid());

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "worldflipper")) continue;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!header || header->magic != MH_MAGIC_64) continue;
        const uintptr_t slide = _dyld_get_image_vmaddr_slide(i);
        g_slide = slide;
        TLog("[RT] main image=%s slide=0x%lx\n", name, slide);

        for (int s = 0; s < NSETTERS; s++) {
            hook_setter(s, slide);
        }
        break;
    }

    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (doc) {
        NSData *d = [NSData dataWithBytes:g_log length:g_len];
        [d writeToFile:[doc stringByAppendingPathComponent:@"render_trace.log"] atomically:YES];
        NSLog(@"[RT] initial log -> %@/render_trace.log", doc);
    }
    fprintf(stderr, "%s", g_log);
    fflush(stderr);
}