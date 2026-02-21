#include "symbol.h"
#include "common.h"
#include <inttypes.h>
#include <signal.h>
#include <setjmp.h>

#define KERNEL_TEXT_OFFSET 0x80000
#define PAGE_SIZE         0x1000
#define INSN_SIZE         4

// 缓存从kallsyms找到的符号
static struct {
    const char *name;
    uint32_t offset;
    int found;
} cached_symbols[] = {
    {"tcp_init_sock", 0, 0},
    {"memblock_reserve", 0, 0},
    {"memblock_free", 0, 0},
    {"memblock_mark_nomap", 0, 0},
    {"memblock_alloc_try_nid", 0, 0},
    {"memblock_alloc", 0, 0},
    {"panic", 0, 0},
    {"rest_init", 0, 0},
    {"kernel_init", 0, 0},
    {"copy_process", 0, 0},
    {"cgroup_post_fork", 0, 0},
    {"avc_denied", 0, 0},
    {"slow_avc_audit", 0, 0},
    {"input_handle_event", 0, 0},
    {"cgroup_init", 0, 0},
    {NULL, 0, 0}
};

static jmp_buf segv_env;
static struct sigaction old_sa;
static int in_segv_handler = 0;

static void segv_handler(int signum, siginfo_t *info, void *context) {
    (void)signum;
    (void)context;
    
    if (!in_segv_handler) {
        in_segv_handler = 1;
        tools_loge("Segmentation fault caught at address: %p\n", info->si_addr);
        in_segv_handler = 0;
        longjmp(segv_env, 1);
    }
}

static void setup_segv_handler(void) {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_sa);
}

static void restore_segv_handler(void) {
    sigaction(SIGSEGV, &old_sa, NULL);
}

// 尝试查找带后缀的符号
static int32_t find_suffixed_symbol_internal(kallsym_t *kallsym, char *img_buf, const char *symbol) {
    char suffixed_name[128];
    
    // 查找带 .isra 后缀的版本
    snprintf(suffixed_name, sizeof(suffixed_name), "%s.isra", symbol);
    int32_t offset = get_symbol_offset(kallsym, img_buf, suffixed_name);
    if (offset > 0) {
        tools_logi("Found %s at offset 0x%x\n", suffixed_name, offset);
        return offset;
    }
    
    // 查找带 .constprop 后缀的版本
    snprintf(suffixed_name, sizeof(suffixed_name), "%s.constprop", symbol);
    offset = get_symbol_offset(kallsym, img_buf, suffixed_name);
    if (offset > 0) {
        tools_logi("Found %s at offset 0x%x\n", suffixed_name, offset);
        return offset;
    }
    
    // 查找带数字后缀的版本
    for (int j = 0; j < 10; j++) {
        snprintf(suffixed_name, sizeof(suffixed_name), "%s.%d", symbol, j);
        offset = get_symbol_offset(kallsym, img_buf, suffixed_name);
        if (offset > 0) {
            tools_logi("Found %s at offset 0x%x\n", suffixed_name, offset);
            return offset;
        }
    }
    
    return 0;
}

// 从内核的kallsyms中提取所有需要的符号
static int extract_symbols_from_kallsyms(kallsym_t *kallsym, char *img_buf) {
    if (!kallsym || !img_buf) return -1;
    
    tools_logi("Extracting symbols from kallsyms...\n");
    
    for (int i = 0; cached_symbols[i].name != NULL; i++) {
        const char *sym_name = cached_symbols[i].name;
        
        // 先尝试直接查找
        int32_t offset = get_symbol_offset(kallsym, img_buf, sym_name);
        
        // 如果没找到，尝试查找带后缀的版本
        if (offset <= 0) {
            offset = find_suffixed_symbol_internal(kallsym, img_buf, sym_name);
        }
        
        if (offset > 0) {
            cached_symbols[i].offset = offset;
            cached_symbols[i].found = 1;
            tools_logi("Cached %s at offset 0x%x\n", sym_name, offset);
        } else {
            tools_loge("Warning: Could not find symbol %s\n", sym_name);
        }
    }
    
    return 0;
}

// 获取符号偏移，只使用kallsyms找到的值
int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    if (!info || !img || !symbol) return 0;
    
    // 先尝试从kallsyms实时获取
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset > 0) {
        tools_logi("Found %s via kallsyms at 0x%x\n", symbol, offset);
        return offset;
    }
    
    // 尝试查找带后缀的版本
    offset = find_suffixed_symbol_internal(info, img, symbol);
    if (offset > 0) {
        return offset;
    }
    
    // 检查是否在我们缓存的列表中
    for (int i = 0; cached_symbols[i].name != NULL; i++) {
        if (strcmp(cached_symbols[i].name, symbol) == 0) {
            if (cached_symbols[i].found) {
                tools_logi("Using cached offset for %s: 0x%x\n", symbol, cached_symbols[i].offset);
                return cached_symbols[i].offset;
            }
            break;
        }
    }
    
    // 特别处理：如果找不到，返回0，让调用者处理
    tools_loge("Warning: Could not find symbol %s\n", symbol);
    return 0;
}

int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
{
    if (!info || !img || !symbol) {
        tools_loge_exit("invalid parameters for symbol %s\n", symbol ? symbol : "null");
    }
    
    // 如果是kallsyms_lookup_name，直接返回错误，因为我们不需要它
    if (strcmp(symbol, "kallsyms_lookup_name") == 0) {
        tools_loge("Error: kallsyms_lookup_name should not be required\n");
        return -1;
    }
    
    int32_t offset = get_symbol_offset_zero(info, img, symbol);
    if (offset > 0) {
        return offset;
    } else {
        tools_loge_exit("no symbol %s found\n", symbol);
    }
}

int32_t try_get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    return get_symbol_offset_zero(info, img, symbol);
}

void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size)
{
    if (!kallsym || !image_buf || !map_start || !max_size) {
        tools_loge("select_map_area: invalid parameters\n");
        return;
    }
    
    tools_logi("select_map_area: looking for tcp_init_sock\n");
    
    // 首先尝试从kallsyms提取所有需要的符号
    extract_symbols_from_kallsyms(kallsym, image_buf);
    
    int32_t addr = get_symbol_offset_exit(kallsym, image_buf, "tcp_init_sock");
    *map_start = align_ceil(addr, 16);
    *max_size = 0x800;
    tools_logi("map_start: 0x%x, max_size: 0x%x\n", *map_start, *max_size);
}

int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
{
    if (!kallsym || !img_buf || !symbol) {
        tools_loge("fillin_map_symbol: invalid parameters\n");
        return -1;
    }
    
    tools_logi("=== fillin_map_symbol start ===\n");
    
    // 设置段错误处理
    setup_segv_handler();
    
    if (setjmp(segv_env) == 0) {
        // 清零结构体
        memset(symbol, 0, sizeof(map_symbol_t));
        
        symbol->memblock_reserve_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_reserve");
        symbol->memblock_free_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_free");
        symbol->memblock_mark_nomap_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_mark_nomap");
        
        // 尝试多种可能的 memblock alloc 函数
        symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc_try_nid");
        if (!symbol->memblock_phys_alloc_relo) {
            symbol->memblock_phys_alloc_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc");
        }
        symbol->memblock_virt_alloc_relo = symbol->memblock_phys_alloc_relo;
        
        if (!symbol->memblock_phys_alloc_relo) {
            tools_loge_exit("no memblock alloc function found");
        }
        
        tools_logi("memblock_reserve: 0x%" PRIx64 "\n", symbol->memblock_reserve_relo);
        tools_logi("memblock_free: 0x%" PRIx64 "\n", symbol->memblock_free_relo);
        tools_logi("memblock_alloc: 0x%" PRIx64 "\n", symbol->memblock_phys_alloc_relo);
        
        if ((is_be() ^ target_is_be)) {
            for (int64_t *pos = (int64_t *)symbol; pos < (int64_t *)(symbol + 1); pos++) {
                *pos = i64swp(*pos);
            }
        }
    } else {
        tools_loge("segfault in fillin_map_symbol\n");
        restore_segv_handler();
        return -1;
    }
    
    restore_segv_handler();
    tools_logi("=== fillin_map_symbol end ===\n");
    return 0;
}

int fillin_patch_config(kallsym_t *kallsym, char *img_buf, int imglen, patch_config_t *symbol, int32_t target_is_be,
                        bool is_android)
{
    if (!kallsym || !img_buf || !symbol) {
        tools_loge("fillin_patch_config: invalid parameters\n");
        return -1;
    }
    
    tools_logi("=== fillin_patch_config start ===\n");
    
    // 设置段错误处理
    setup_segv_handler();
    
    if (setjmp(segv_env) == 0) {
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
        
        // copy_process可能找不到，尝试使用cgroup_post_fork作为替代
        symbol->copy_process = get_symbol_offset_zero(kallsym, img_buf, "copy_process");
        if (!symbol->copy_process) {
            symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
            if (symbol->cgroup_post_fork) {
                tools_logi("Using cgroup_post_fork (0x%" PRIx64 ") as fallback for copy_process\n", 
                          symbol->cgroup_post_fork);
            }
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
        tools_logi("cgroup_post_fork: 0x%" PRIx64 "\n", symbol->cgroup_post_fork);
        tools_logi("avc_denied: 0x%" PRIx64 "\n", symbol->avc_denied);
        tools_logi("input_handle_event: 0x%" PRIx64 "\n", symbol->input_handle_event);
        
        if ((is_be() ^ target_is_be)) {
            for (int64_t *pos = (int64_t *)symbol; pos < (int64_t *)(symbol + 1); pos++) {
                *pos = i64swp(*pos);
            }
        }
    } else {
        tools_loge("segfault in fillin_patch_config\n");
        restore_segv_handler();
        return -1;
    }
    
    restore_segv_handler();
    tools_logi("=== fillin_patch_config end ===\n");
    return 0;
}

// 保留但不再使用
int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    return 0;
}
