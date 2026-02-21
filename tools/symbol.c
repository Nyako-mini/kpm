#include "symbol.h"
#include "common.h"
#include <inttypes.h>

#define CODE_START        0xffffff8008000000
#define CODE_END          0xffffff800f000000
#define KERNEL_TEXT_OFFSET 0x80000
#define PAGE_SIZE         0x1000
#define INSN_SIZE         4

struct symbol_pattern {
    const char *name;
    uint32_t *pattern;
    int pattern_len;
    uint32_t *mask;
};

struct on_each_symbol_struct {
    const char *symbol;
    uint64_t addr;
};

static uint32_t panic_pattern[] = {0xd2800015, 0xd503201f, 0xf9401776};
static uint32_t panic_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t memblock_reserve_pattern[] = {0xf81f0ffe, 0xf9000bf3, 0xf94013f3};
static uint32_t memblock_reserve_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t memblock_free_pattern[] = {0xaa0003f5, 0xf9000bf3, 0xaa0103f4};
static uint32_t memblock_free_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t memblock_alloc_try_nid_pattern[] = {0xaa0003f9, 0xaa0203f5, 0xaa0303f6};
static uint32_t memblock_alloc_try_nid_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t rest_init_pattern[] = {0xd5384100, 0xb2401bf5, 0xd5033cbf};
static uint32_t rest_init_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t kernel_init_pattern[] = {0xaa0103f3, 0x94000001, 0xaa0003f4};
static uint32_t kernel_init_mask[] = {0xffffffff, 0xff000000, 0xffffffff};

static uint32_t copy_process_pattern[] = {0xd15b42b4, 0xb4000100, 0xf94013e0};
static uint32_t copy_process_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t avc_denied_pattern[] = {0xaa1403e0, 0xf9400b94, 0xb50002b4};
static uint32_t avc_denied_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t slow_avc_audit_pattern[] = {0xaa1303e0, 0xaa1403e1, 0x94000001};
static uint32_t slow_avc_audit_mask[] = {0xffffffff, 0xffffffff, 0xff000000};

static uint32_t input_handle_event_pattern[] = {0xaa1503f4, 0xaa1503f5, 0x94000001};
static uint32_t input_handle_event_mask[] = {0xffffffff, 0xffffffff, 0xff000000};

static uint32_t cgroup_init_pattern[] = {0xaa1a03e3, 0x94000001, 0xf9402ba0};
static uint32_t cgroup_init_mask[] = {0xffffffff, 0xff000000, 0xffffffff};

static uint32_t cgroup_post_fork_pattern[] = {0xaa1503f5, 0x52800035, 0x52800034};
static uint32_t cgroup_post_fork_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static uint32_t tcp_init_sock_pattern[] = {0xd503233f, 0xf81f0ffe, 0xaa0003f3};
static uint32_t tcp_init_sock_mask[] = {0xffffffff, 0xffffffff, 0xffffffff};

static struct symbol_pattern patterns[] = {
    {"panic", panic_pattern, 3, panic_mask},
    {"memblock_reserve", memblock_reserve_pattern, 3, memblock_reserve_mask},
    {"memblock_free", memblock_free_pattern, 3, memblock_free_mask},
    {"memblock_alloc_try_nid", memblock_alloc_try_nid_pattern, 3, memblock_alloc_try_nid_mask},
    {"rest_init", rest_init_pattern, 3, rest_init_mask},
    {"kernel_init", kernel_init_pattern, 3, kernel_init_mask},
    {"copy_process", copy_process_pattern, 3, copy_process_mask},
    {"avc_denied", avc_denied_pattern, 3, avc_denied_mask},
    {"slow_avc_audit", slow_avc_audit_pattern, 3, slow_avc_audit_mask},
    {"input_handle_event", input_handle_event_pattern, 3, input_handle_event_mask},
    {"cgroup_init", cgroup_init_pattern, 3, cgroup_init_mask},
    {"cgroup_post_fork", cgroup_post_fork_pattern, 3, cgroup_post_fork_mask},
    {"tcp_init_sock", tcp_init_sock_pattern, 3, tcp_init_sock_mask},
    {NULL, NULL, 0, NULL}
};

static uint32_t *get_pattern(const char *symbol, int *len, uint32_t **mask) {
    for (int i = 0; patterns[i].name != NULL; i++) {
        if (strcmp(patterns[i].name, symbol) == 0) {
            *len = patterns[i].pattern_len;
            *mask = patterns[i].mask;
            return patterns[i].pattern;
        }
    }
    return NULL;
}

static uint64_t scan_pattern_in_range(char *base, uint32_t *pattern, uint32_t *mask, int pattern_len) {
    if (!base || !pattern || !mask || pattern_len <= 0) return 0;
    
    uint32_t *start = (uint32_t *)(base + KERNEL_TEXT_OFFSET);
    uint32_t *end = (uint32_t *)(base + 0x2800000); // ~40MB scan range
    
    for (uint32_t *p = start; p < end - pattern_len; p++) {
        int match = 1;
        for (int i = 0; i < pattern_len; i++) {
            if ((p[i] & mask[i]) != (pattern[i] & mask[i])) {
                match = 0;
                break;
            }
        }
        if (match) {
            return (uint64_t)((char *)p - base);
        }
    }
    return 0;
}

static int32_t find_symbol_by_pattern(char *img_buf, const char *symbol) {
    if (!img_buf || !symbol) return 0;
    
    int pattern_len;
    uint32_t *mask;
    uint32_t *pattern = get_pattern(symbol, &pattern_len, &mask);
    if (!pattern) return 0;
    
    return scan_pattern_in_range(img_buf, pattern, mask, pattern_len);
}

int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    // 完全忽略 kallsyms，只使用特征码匹配
    return find_symbol_by_pattern(img, symbol);
}

int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset_zero(info, img, symbol);
    if (offset > 0) {
        tools_logi("found %s at offset 0x%x\n", symbol, offset);
        return offset;
    } else {
        tools_loge_exit("no symbol %s found by pattern matching\n", symbol);
    }
}

int32_t try_get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    return get_symbol_offset_zero(info, img, symbol);
}

void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size)
{
    if (!kallsym || !image_buf || !map_start || !max_size) return;
    
    int32_t addr = get_symbol_offset_exit(kallsym, image_buf, "tcp_init_sock");
    *map_start = align_ceil(addr, 16);
    *max_size = 0x800;
    tools_logi("map_start: 0x%x, max_size: 0x%x\n", *map_start, *max_size);
}

int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
{
    if (!kallsym || !img_buf || !symbol) return -1;
    
    tools_logi("filling map symbols using pattern matching...\n");
    
    symbol->memblock_reserve_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_reserve");
    symbol->memblock_free_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_free");
    symbol->memblock_mark_nomap_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_mark_nomap");
    
    // 尝试多种可能的 memblock alloc 函数
    symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc_try_nid");
    symbol->memblock_virt_alloc_relo = symbol->memblock_phys_alloc_relo;
    
    if (!symbol->memblock_phys_alloc_relo) {
        // 尝试其他可能的名称
        symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc");
        symbol->memblock_virt_alloc_relo = symbol->memblock_phys_alloc_relo;
    }
    
    if (!symbol->memblock_phys_alloc_relo)
        tools_loge_exit("no memblock alloc function found");
    
    tools_logi("memblock_reserve: 0x%" PRIx64 "\n", symbol->memblock_reserve_relo);
    tools_logi("memblock_free: 0x%" PRIx64 "\n", symbol->memblock_free_relo);
    tools_logi("memblock_alloc: 0x%" PRIx64 "\n", symbol->memblock_phys_alloc_relo);
    
    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos < (int64_t *)(symbol + 1); pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

int fillin_patch_config(kallsym_t *kallsym, char *img_buf, int imglen, patch_config_t *symbol, int32_t target_is_be,
                        bool is_android)
{
    if (!kallsym || !img_buf || !symbol) return -1;
    
    tools_logi("filling patch config using pattern matching...\n");
    
    // 清零结构体
    memset(symbol, 0, sizeof(patch_config_t));
    
    symbol->panic = get_symbol_offset_zero(kallsym, img_buf, "panic");
    symbol->rest_init = get_symbol_offset_zero(kallsym, img_buf, "rest_init");
    
    if (!symbol->rest_init) {
        symbol->cgroup_init = get_symbol_offset_zero(kallsym, img_buf, "cgroup_init");
    }
    
    if (!symbol->rest_init && !symbol->cgroup_init) {
        tools_loge("warning: no rest_init/cgroup_init found\n");
    }
    
    symbol->kernel_init = get_symbol_offset_zero(kallsym, img_buf, "kernel_init");
    symbol->copy_process = get_symbol_offset_zero(kallsym, img_buf, "copy_process");
    
    if (!symbol->copy_process) {
        symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
    }
    
    if (is_android) {
        symbol->avc_denied = get_symbol_offset_zero(kallsym, img_buf, "avc_denied");
        if (!symbol->avc_denied) {
            tools_loge_exit("no avc_denied found for Android kernel\n");
        }
    }
    
    symbol->slow_avc_audit = get_symbol_offset_zero(kallsym, img_buf, "slow_avc_audit");
    symbol->input_handle_event = get_symbol_offset_zero(kallsym, img_buf, "input_handle_event");
    
    // 打印找到的符号
    tools_logi("panic: 0x%" PRIx64 "\n", symbol->panic);
    tools_logi("rest_init: 0x%" PRIx64 "\n", symbol->rest_init);
    tools_logi("kernel_init: 0x%" PRIx64 "\n", symbol->kernel_init);
    tools_logi("copy_process: 0x%" PRIx64 "\n", symbol->copy_process);
    tools_logi("avc_denied: 0x%" PRIx64 "\n", symbol->avc_denied);
    tools_logi("input_handle_event: 0x%" PRIx64 "\n", symbol->input_handle_event);
    
    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos < (int64_t *)(symbol + 1); pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

// 完全移除对 kallsyms 的依赖
int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    return 0; // 不再使用
}
