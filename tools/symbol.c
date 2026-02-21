#include "symbol.h"
#include "common.h"

#define CODE_START        0xffffff8008000000
#define CODE_END          0xffffff800f000000
#define PAGE_SIZE         0x1000
#define INSN_SIZE         4
#define MAX_SCAN_SIZE     0x100000

struct symbol_pattern {
    const char *name;
    uint32_t *pattern;
    int pattern_len;
};

struct on_each_symbol_struct {
    const char *symbol;
    uint64_t addr;
};

static uint32_t panic_pattern[] = {0xd2800015, 0xd503201f, 0xf9401776};
static int panic_len = 3;

static uint32_t memblock_reserve_pattern[] = {0xf81f0ffe, 0xf9000bf3, 0xf94013f3};
static int memblock_reserve_len = 3;

static uint32_t memblock_free_pattern[] = {0xaa0003f5, 0xf9000bf3, 0xaa0103f4};
static int memblock_free_len = 3;

static uint32_t memblock_alloc_try_nid_pattern[] = {0xaa0003f9, 0xaa0203f5, 0xaa0303f6};
static int memblock_alloc_try_nid_len = 3;

static uint32_t rest_init_pattern[] = {0xd5384100, 0xb2401bf5, 0xd5033cbf};
static int rest_init_len = 3;

static uint32_t kernel_init_pattern[] = {0xaa0103f3, 0x97fffffe, 0xaa0003f4};
static int kernel_init_len = 3;

static uint32_t copy_process_pattern[] = {0xd15b42b4, 0xb4000100, 0xf94013e0};
static int copy_process_len = 3;

static uint32_t avc_denied_pattern[] = {0xaa1403e0, 0xf9400b94, 0xb50002b4};
static int avc_denied_len = 3;

static uint32_t slow_avc_audit_pattern[] = {0xaa1303e0, 0xaa1403e1, 0x94000001};
static int slow_avc_audit_len = 3;

static uint32_t input_handle_event_pattern[] = {0xaa1503f4, 0xaa1503f5, 0xf0000001};
static int input_handle_event_len = 3;

static uint32_t cgroup_init_pattern[] = {0xaa1a03e3, 0x97fffffe, 0xf9402ba0};
static int cgroup_init_len = 3;

static uint32_t cgroup_post_fork_pattern[] = {0xaa1503f5, 0x52800035, 0x52800034};
static int cgroup_post_fork_len = 3;

static uint32_t cfi_failure_pattern[] = {0xd5384100, 0xb4000100, 0xf94013e0};
static int cfi_failure_len = 3;

static uint32_t *get_pattern(const char *symbol, int *len) {
    if (!strcmp(symbol, "panic")) { *len = panic_len; return panic_pattern; }
    if (!strcmp(symbol, "memblock_reserve")) { *len = memblock_reserve_len; return memblock_reserve_pattern; }
    if (!strcmp(symbol, "memblock_free")) { *len = memblock_free_len; return memblock_free_pattern; }
    if (!strcmp(symbol, "memblock_alloc_try_nid")) { *len = memblock_alloc_try_nid_len; return memblock_alloc_try_nid_pattern; }
    if (!strcmp(symbol, "rest_init")) { *len = rest_init_len; return rest_init_pattern; }
    if (!strcmp(symbol, "kernel_init")) { *len = kernel_init_len; return kernel_init_pattern; }
    if (!strcmp(symbol, "copy_process")) { *len = copy_process_len; return copy_process_pattern; }
    if (!strcmp(symbol, "avc_denied")) { *len = avc_denied_len; return avc_denied_pattern; }
    if (!strcmp(symbol, "slow_avc_audit")) { *len = slow_avc_audit_len; return slow_avc_audit_pattern; }
    if (!strcmp(symbol, "input_handle_event")) { *len = input_handle_event_len; return input_handle_event_pattern; }
    if (!strcmp(symbol, "cgroup_init")) { *len = cgroup_init_len; return cgroup_init_pattern; }
    if (!strcmp(symbol, "cgroup_post_fork")) { *len = cgroup_post_fork_len; return cgroup_post_fork_pattern; }
    if (strstr(symbol, "cfi")) { *len = cfi_failure_len; return cfi_failure_pattern; }
    return NULL;
}

static uint64_t scan_pattern_in_range(uint32_t *start, uint32_t *end, uint32_t *pattern, int pattern_len) {
    uint32_t *p = start;
    
    while (p < end - pattern_len) {
        int match = 1;
        for (int i = 0; i < pattern_len; i++) {
            if (p[i] != pattern[i]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return (uint64_t)p;
        }
        p += 4;
    }
    return 0;
}

static uint64_t find_by_text_reference(uint64_t known_addr, const char *target_sym) {
    uint32_t *code = (uint32_t *)known_addr;
    
    for (int i = 0; i < 0x200; i++) {
        if ((code[i] & 0xfc000000) == 0x94000000) {
            int32_t offset = (code[i] & 0x3ffffff) << 2;
            if (code[i] & 0x2000000) offset |= 0xfc000000;
            
            uint64_t target = known_addr + (i * 4) + offset;
            
            if (target > CODE_START && target < CODE_END) {
                uint32_t *target_code = (uint32_t *)target;
                if (target_code[0] == 0xd503201f || target_code[0] == 0xd65f03c0) {
                    return target;
                }
            }
        }
    }
    return 0;
}

static int32_t on_each_symbol_callbackup(int32_t index, char type, const char *symbol, int32_t offset, void *userdata)
{
    struct on_each_symbol_struct *data = (struct on_each_symbol_struct *)userdata;
    int len = strlen(data->symbol);
    if (strstr(symbol, data->symbol) == symbol && (symbol[len] == '.' || symbol[len] == '$') &&
        !strstr(symbol, ".cfi_jt")) {
        tools_logi("%s -> %s: type: %c, offset: 0x%08x\n", data->symbol, symbol, type, offset);
        data->addr = offset;
        return 1;
    }
    return 0;
}

int32_t find_suffixed_symbol(kallsym_t *kallsym, char *img_buf, const char *symbol)
{
    struct on_each_symbol_struct udata = { symbol, 0 };
    on_each_symbol(kallsym, img_buf, &udata, on_each_symbol_callbackup);
    return udata.addr;
}

static int32_t find_by_pattern(const char *symbol) {
    int pattern_len;
    uint32_t *pattern = get_pattern(symbol, &pattern_len);
    if (!pattern) return 0;
    
    uint64_t addr = scan_pattern_in_range((uint32_t *)CODE_START, (uint32_t *)CODE_END, pattern, pattern_len);
    return addr ? addr - CODE_START : 0;
}

static int32_t find_memblock_phys_alloc(kallsym_t *kallsym, char *img_buf) {
    int32_t addr = find_by_pattern("memblock_alloc_try_nid");
    if (addr) return addr;
    
    addr = get_symbol_offset(kallsym, img_buf, "memblock_alloc_try_nid");
    if (addr > 0) return addr;
    
    addr = find_suffixed_symbol(kallsym, img_buf, "memblock_alloc_try_nid");
    return addr;
}

int32_t get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset > 0) return offset;
    
    offset = find_by_pattern(symbol);
    if (offset > 0) return offset;
    
    offset = find_suffixed_symbol(info, img, symbol);
    return offset > 0 ? offset : 0;
}

int32_t get_symbol_offset_exit(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset_zero(info, img, symbol);
    if (offset >= 0) {
        return offset;
    } else {
        tools_loge_exit("no symbol %s\n", symbol);
    }
}

int32_t try_get_symbol_offset_zero(kallsym_t *info, char *img, char *symbol)
{
    int32_t offset = get_symbol_offset(info, img, symbol);
    if (offset > 0) return offset;
    
    offset = find_by_pattern(symbol);
    if (offset > 0) return offset;
    
    return find_suffixed_symbol(info, img, symbol);
}

void select_map_area(kallsym_t *kallsym, char *image_buf, int32_t *map_start, int32_t *max_size)
{
    int32_t addr = 0x200;
    addr = get_symbol_offset_exit(kallsym, image_buf, "tcp_init_sock");
    *map_start = align_ceil(addr, 16);
    *max_size = 0x800;
}

int fillin_map_symbol(kallsym_t *kallsym, char *img_buf, map_symbol_t *symbol, int32_t target_is_be)
{
    symbol->memblock_reserve_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_reserve");
    symbol->memblock_free_relo = get_symbol_offset_exit(kallsym, img_buf, "memblock_free");

    symbol->memblock_mark_nomap_relo = get_symbol_offset_zero(kallsym, img_buf, "memblock_mark_nomap");

    symbol->memblock_phys_alloc_relo = find_memblock_phys_alloc(kallsym, img_buf);
    symbol->memblock_virt_alloc_relo = find_memblock_phys_alloc(kallsym, img_buf);
    if (!symbol->memblock_phys_alloc_relo && !symbol->memblock_virt_alloc_relo)
        tools_loge_exit("no symbol memblock_alloc");

    uint64_t memblock_alloc_try_nid = get_symbol_offset_zero(kallsym, img_buf, "memblock_alloc_try_nid");

    if (!symbol->memblock_phys_alloc_relo) symbol->memblock_phys_alloc_relo = memblock_alloc_try_nid;
    if (!symbol->memblock_virt_alloc_relo) symbol->memblock_virt_alloc_relo = memblock_alloc_try_nid;
    if (!symbol->memblock_phys_alloc_relo && !symbol->memblock_virt_alloc_relo)
        tools_loge_exit("no symbol memblock_alloc");

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}

static int get_cand_arr_symbol_offset_zero(kallsym_t *kallsym, char *img_buf, char **cand_arr, int cand_num)
{
    int offset = 0;
    for (int i = 0; i < cand_num; i++) {
        offset = get_symbol_offset_zero(kallsym, img_buf, cand_arr[i]);
        if (offset) break;
    }
    return offset;
}

int fillin_patch_config(kallsym_t *kallsym, char *img_buf, int imglen, patch_config_t *symbol, int32_t target_is_be,
                        bool is_android)
{
    symbol->panic = get_symbol_offset_zero(kallsym, img_buf, "panic");

    symbol->rest_init = try_get_symbol_offset_zero(kallsym, img_buf, "rest_init");
    if (!symbol->rest_init) symbol->cgroup_init = try_get_symbol_offset_zero(kallsym, img_buf, "cgroup_init");
    if (!symbol->rest_init && !symbol->cgroup_init) tools_loge_exit("no symbol rest_init");

    symbol->kernel_init = try_get_symbol_offset_zero(kallsym, img_buf, "kernel_init");

    symbol->report_cfi_failure = get_symbol_offset_zero(kallsym, img_buf, "report_cfi_failure");
    symbol->__cfi_slowpath_diag = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath_diag");
    symbol->__cfi_slowpath = get_symbol_offset_zero(kallsym, img_buf, "__cfi_slowpath");

    symbol->copy_process = try_get_symbol_offset_zero(kallsym, img_buf, "copy_process");
    if (!symbol->copy_process) symbol->cgroup_post_fork = get_symbol_offset_zero(kallsym, img_buf, "cgroup_post_fork");
    if (!symbol->copy_process && !symbol->cgroup_post_fork) tools_loge_exit("no symbol copy_process");

    symbol->avc_denied = try_get_symbol_offset_zero(kallsym, img_buf, "avc_denied");
    if (!symbol->avc_denied && is_android) tools_loge_exit("no symbol avc_denied");

    symbol->slow_avc_audit = try_get_symbol_offset_zero(kallsym, img_buf, "slow_avc_audit");

    symbol->input_handle_event = get_symbol_offset_zero(kallsym, img_buf, "input_handle_event");

    if ((is_be() ^ target_is_be)) {
        for (int64_t *pos = (int64_t *)symbol; pos <= (int64_t *)symbol; pos++) {
            *pos = i64swp(*pos);
        }
    }
    return 0;
}
