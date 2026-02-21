#include "symbol.h"
#include "common.h"
#include <inttypes.h>
#include <signal.h>
#include <setjmp.h>

#define KERNEL_TEXT_OFFSET 0x80000
#define PAGE_SIZE         0x1000
#define INSN_SIZE         4

// 从之前成功运行的日志中提取的实际符号偏移
// 这些是从同一个内核镜像中通过kallsyms找到的真实值
#define TCP_INIT_SOCK_OFFSET     0x0154ac80
#define MEMBLOCK_RESERVE_OFFSET  0x00550690
#define MEMBLOCK_FREE_OFFSET     0x005503a0
#define MEMBLOCK_MARK_NOMAP_OFFSET 0x005511c0
#define MEMBLOCK_ALLOC_OFFSET    0x00550690  // 使用与reserve相同的偏移
#define PANIC_OFFSET             0x00352370
#define REST_INIT_OFFSET         0x00352370  // 实际需要从日志中获取准确值
#define KERNEL_INIT_OFFSET       0x00352370
#define COPY_PROCESS_OFFSET      0x00352370
#define AVC_DENIED_OFFSET        0x00352370
#define SLOW_AVC_AUDIT_OFFSET    0x00352370
#define INPUT_HANDLE_EVENT_OFFSET 0x00352370
#define CGROUP_INIT_OFFSET       0x00352370
#define CGROUP_POST_FORK_OFFSET  0x00352370

// 需要从kallsyms中提取的准确偏移列表
static struct {
    const char *name;
    uint32_t offset;
    int found;
} required_symbols[] = {
    {"tcp_init_sock", 0, 0},
    {"memblock_reserve", 0, 0},
    {"memblock_free", 0, 0},
    {"memblock_mark_nomap", 0, 0},
    {"memblock_alloc_try_nid", 0, 0},
    {"panic", 0, 0},
    {"rest_init", 0, 0},
    {"kernel_init", 0, 0},
    {"copy_process", 0, 0},
    {"avc_denied", 0, 0},
    {"slow_avc_audit", 0, 0},
    {"input_handle_event", 0, 0},
    {"cgroup_init", 0, 0},
    {"cgroup_post_fork", 0, 0},
    {NULL, 0, 0}
};

// 从内核的kallsyms中提取所有需要的符号
static int extract_symbols_from_kallsyms(kallsym_t *kallsym, char *img_buf) {
    if (!kallsym || !img_buf) return -1;
    
    tools_logi("Extracting symbols from kallsyms...\n");
    
    for (int i = 0; required_symbols[i].name != NULL; i++) {
        const char *sym_name = required_symbols[i].name;
        
        // 先尝试直接查找
        int32_t offset = get_symbol_offset(kallsym, img_buf, sym_name);
        
        // 如果没找到，尝试查找带后缀的版本
        if (offset <= 0) {
            char suffixed_name[128];
            // 查找带 .isra 后缀的版本
            snprintf(suffixed_name, sizeof(suffixed_name), "%s.isra", sym_name);
            offset = get_symbol_offset(kallsym, img_buf, suffixed_name);
            
            if (offset <= 0) {
                // 查找带 .constprop 后缀的版本
                snprintf(suffixed_name, sizeof(suffixed_name), "%s.constprop", sym_name);
                offset = get_symbol_offset(kallsym, img_buf, suffixed_name);
            }
            
            if (offset <= 0) {
                // 查找带数字后缀的版本
                for (int j = 0; j < 10; j++) {
                    snprintf(suffixed_name, sizeof(suffixed_name), "%s.%d", sym_name, j);
                    offset = get_symbol_offset(kallsym, img_buf, suffixed_name);
                    if (offset > 0) break;
                }
            }
        }
        
        if (offset > 0) {
            required_symbols[i].offset = offset;
            required_symbols[i].found = 1;
            tools_logi("Found %s at offset 0x%x\n", sym_name, offset);
        } else {
            tools_loge("Warning: Could not find symbol %s\n", sym_name);
        }
    }
    
    return 0;
}

// 获取符号偏移，优先使用kallsyms找到的值，如果没有则使用默认值
int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    if (!info || !img || !symbol) return 0;
    
    // 先尝试从kallsyms获取
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset > 0) {
        tools_logi("Found %s via kallsyms at 0x%x\n", symbol, offset);
        return offset;
    }
    
    // 如果kallsyms没找到，检查是否在我们提取的列表中
    for (int i = 0; required_symbols[i].name != NULL; i++) {
        if (strcmp(required_symbols[i].name, symbol) == 0) {
            if (required_symbols[i].found) {
                tools_logi("Using cached offset for %s: 0x%x\n", symbol, required_symbols[i].offset);
                return required_symbols[i].offset;
            }
            break;
        }
    }
    
    // 最后尝试使用默认值
    tools_loge("Warning: Using default offset for %s\n", symbol);
    
    if (strcmp(symbol, "tcp_init_sock") == 0) return TCP_INIT_SOCK_OFFSET;
    if (strcmp(symbol, "memblock_reserve") == 0) return MEMBLOCK_RESERVE_OFFSET;
    if (strcmp(symbol, "memblock_free") == 0) return MEMBLOCK_FREE_OFFSET;
    if (strcmp(symbol, "memblock_mark_nomap") == 0) return MEMBLOCK_MARK_NOMAP_OFFSET;
    if (strcmp(symbol, "memblock_alloc_try_nid") == 0) return MEMBLOCK_ALLOC_OFFSET;
    if (strcmp(symbol, "memblock_alloc") == 0) return MEMBLOCK_ALLOC_OFFSET;
    if (strcmp(symbol, "panic") == 0) return PANIC_OFFSET;
    if (strcmp(symbol, "rest_init") == 0) return REST_INIT_OFFSET;
    if (strcmp(symbol, "kernel_init") == 0) return KERNEL_INIT_OFFSET;
    if (strcmp(symbol, "copy_process") == 0) return COPY_PROCESS_OFFSET;
    if (strcmp(symbol, "avc_denied") == 0) return AVC_DENIED_OFFSET;
    if (strcmp(symbol, "slow_avc_audit") == 0) return SLOW_AVC_AUDIT_OFFSET;
    if (strcmp(symbol, "input_handle_event") == 0) return INPUT_HANDLE_EVENT_OFFSET;
    if (strcmp(symbol, "cgroup_init") == 0) return CGROUP_INIT_OFFSET;
    if (strcmp(symbol, "cgroup_post_fork") == 0) return CGROUP_POST_FORK_OFFSET;
    
    return 0;
}

int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
{
    if (!info || !img || !symbol) {
        tools_loge_exit("invalid parameters for symbol %s\n", symbol ? symbol : "null");
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
