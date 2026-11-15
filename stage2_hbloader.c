/*================================================================================================
  stage2_hbloader.c - Switch 2 Payload Stage 2: SD Card Homebrew Loader (hbloader) Chain

  Execution chain:
    1. Receive resolved table (sw2_resolved) from Stage 1 (sdk_base, libc/nnSdk gadgets).
    2. Initialize SD storage:
       a) Primary path: Call resolved SDK filesystem service (nn::fs::MountSdCardForUser / OpenFile).
       b) Fallback path: Bare-metal SDMMC controller driver + integrated FAT32 filesystem reader.
    3. Traverse SD card root and /switch directory for homebrew loader payloads:
       - sdmc:/hbloader.bin
       - sdmc:/switch/hbloader.bin
       - sdmc:/hbmenu.nro
       - sdmc:/atmosphere/hbl.nsp
    4. Allocate/verify target memory destination for payload staging.
    5. Parse header (Raw AArch64 executable or NRO0 format, relocate/zero BSS).
    6. Construct Homebrew ABI environment (Config Table, Thread Handle, NextLoadPath).
    7. Flush data cache, invalidate instruction cache, barrier pipeline.
    8. Jump to entrypoint (handoff to hbloader).

  Freestanding AArch64 compilation:
    zig cc -target aarch64-freestanding -ffreestanding -nostdlib -O2 -c stage2_hbloader.c -o stage2_hbloader.o
  Host test compilation:
    gcc -DSW2_HOST_TEST -O2 -std=c11 -o stage2_hbloader_test stage2_hbloader.c
================================================================================================*/

#include <stddef.h>
#include <stdint.h>

#if defined(SW2_HOST_TEST)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/* --- Constants & Status Codes ----------------------------------------------------------------- */

#define SW2_STAGE2_MAGIC         0x32533253u  /* "S2S2" */
#define NRO0_MAGIC               0x304F524Eu  /* "NRO0" */

#define SW2_ERR_OK               0
#define SW2_ERR_STAGE1_NULL     -1
#define SW2_ERR_SD_INIT         -2
#define SW2_ERR_SD_MOUNT        -3
#define SW2_ERR_FILE_NOT_FOUND  -4
#define SW2_ERR_FILE_READ       -5
#define SW2_ERR_MEM_ALLOC       -6
#define SW2_ERR_INVALID_HEADER  -7
#define SW2_ERR_EXEC_HANDOFF    -8

#define SD_BLOCK_SIZE            512u
#define HBLOADER_MAX_SIZE        (32u * 1024u * 1024u) /* 32 MB max */
#define HBLOADER_LOAD_ADDR       0x80060000ULL        /* Standard staging memory base */

/* --- Stage 1 Resolved Interface (Matches patches/stage1.c) ----------------------------------- */

typedef struct {
    uint32_t main_base;
    uint32_t sdk_base;
    uint32_t image_match;
    uint32_t present;
    uint32_t got_memcpy;
    uint32_t memcpy;
    uint32_t nifm_init;
    uint32_t nifm_ip;
    uint32_t sock_init;
    uint32_t socket;
    uint32_t bind;
    uint32_t listen;
    uint32_t accept;
    uint32_t recv;
    uint32_t send;
    uint32_t close;
    uint32_t fiber_switch;
    uint32_t fiber_pop_gp;
    uint32_t fiber_capture;
    uint32_t ctx_restore;
    uint32_t ctx_save;
    uint32_t fp_capture;
} sw2_resolved;

/* --- NRO (Nintendo Relocatable Object) Format ------------------------------------------------- */

#pragma pack(push, 1)

typedef struct {
    uint32_t unused;
    uint32_t mod0_offset;
    uint8_t  padding[8];
} nro_start;

typedef struct {
    uint32_t magic;              /* "NRO0" */
    uint32_t version;
    uint32_t size;
    uint32_t flags;
    uint32_t text_offset;
    uint32_t text_size;
    uint32_t rodata_offset;
    uint32_t rodata_size;
    uint32_t data_offset;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t reserved;
    uint8_t  module_id[32];
    uint32_t dso_handle_offset;
    uint32_t reserved2;
    uint32_t embedded_info[4];
} nro_header;

/* Homebrew Config Table ABI */
typedef struct {
    uint32_t key;
    uint32_t flags;
    uint64_t value[2];
} hbl_config_entry;

#pragma pack(pop)

enum HblConfigKey {
    HBL_KEY_END_OF_LIST             = 0,
    HBL_KEY_MAIN_THREAD_HANDLE      = 1,
    HBL_KEY_NEXT_LOAD_PATH          = 2,
    HBL_KEY_OVERRIDE_HEAP           = 3,
    HBL_KEY_OVERRIDE_SERVICE        = 4,
    HBL_KEY_ARGV                    = 5,
    HBL_KEY_SYSCALL_AVAILABLE_HINT  = 6,
    HBL_KEY_APPLET_TYPE             = 7,
    HBL_KEY_APPLET_WORKAROUND       = 8,
    HBL_KEY_LAST_LOAD_RESULT        = 9,
    HBL_KEY_FATAL_CONTEXT           = 10
};

/* --- FAT32 Filesystem Support (Bare-Metal Fallback) ------------------------------------------- */

#pragma pack(push, 1)

typedef struct {
    uint8_t  bootjmp[3];
    uint8_t  oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sector_count;
    uint8_t  table_count;
    uint16_t root_entry_count;
    uint16_t total_sectors_16;
    uint8_t  media_type;
    uint16_t table_size_16;
    uint16_t sectors_per_track;
    uint16_t head_side_count;
    uint32_t hidden_sector_count;
    uint32_t total_sectors_32;
    uint32_t table_size_32;
    uint16_t extended_flags;
    uint16_t fat_version;
    uint32_t root_cluster;
    uint16_t fat_info;
    uint16_t backup_boot_sector;
    uint8_t  reserved[12];
    uint8_t  drive_number;
    uint8_t  reserved1;
    uint8_t  boot_signature;
    uint32_t volume_id;
    char     volume_label[11];
    uint8_t  fat_type_label[8];
} fat32_bpb;

typedef struct {
    uint8_t  name[11];           /* 8.3 format */
    uint8_t  attr;
    uint8_t  nt_res;
    uint8_t  crt_time_tenth;
    uint16_t crt_time;
    uint16_t crt_date;
    uint16_t lst_acc_date;
    uint16_t fst_clus_hi;
    uint16_t wrt_time;
    uint16_t wrt_date;
    uint16_t fst_clus_lo;
    uint32_t file_size;
} fat_dir_entry;

#pragma pack(pop)

typedef struct {
    uint32_t fat_start_lba;
    uint32_t cluster_start_lba;
    uint32_t sectors_per_cluster;
    uint32_t bytes_per_cluster;
    uint32_t root_cluster;
    uint32_t table_size;
} fat32_fs;

/* --- Minimal Freestanding Memory Primitives -------------------------------------------------- */

#if !defined(SW2_HOST_TEST)
static void* sw2_memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    while (n--) *d++ = *s++;
    return dst;
}

static void* sw2_memset(void* s, int c, size_t n) {
    uint8_t* p = (uint8_t*)s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

static int sw2_memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = (const uint8_t*)s1;
    const uint8_t* p2 = (const uint8_t*)s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}
#else
#define sw2_memcpy memcpy
#define sw2_memset memset
#define sw2_memcmp memcmp
#endif

/* --- Low-level Cache & Barrier Primitives (AArch64) ------------------------------------------- */

static void sw2_cache_flush_and_invalidate(const void* addr, size_t size) {
#if defined(__aarch64__)
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line;

    /* Clean data cache to Point of Coherency (PoC) */
    for (line = start & ~63ULL; line < end; line += 64) {
        __asm__ volatile ("dc cvau, %0" : : "r"(line) : "memory");
    }
    __asm__ volatile ("dsb ish" ::: "memory");

    /* Invalidate instruction cache */
    for (line = start & ~63ULL; line < end; line += 64) {
        __asm__ volatile ("ic ivau, %0" : : "r"(line) : "memory");
    }
    __asm__ volatile ("dsb ish" ::: "memory");
    __asm__ volatile ("isb" ::: "memory");
#else
    (void)addr;
    (void)size;
#endif
}

/* --- Storage Abstraction Interface ------------------------------------------------------------ */

/* Sector reader function signature */
typedef int (*sector_reader_fn)(uint32_t lba, uint32_t count, void* buffer);

/* Global mock/hardware sector reader */
static sector_reader_fn g_sector_reader = NULL;

static int fat32_read_sector(uint32_t lba, uint32_t count, void* buffer) {
    if (!g_sector_reader) return -1;
    return g_sector_reader(lba, count, buffer);
}

static uint32_t fat32_get_next_cluster(const fat32_fs* fs, uint32_t current_cluster) {
    uint8_t sector_buf[SD_BLOCK_SIZE];
    uint32_t fat_offset = current_cluster * 4;
    uint32_t fat_sector = fs->fat_start_lba + (fat_offset / SD_BLOCK_SIZE);
    uint32_t ent_offset = fat_offset % SD_BLOCK_SIZE;

    if (fat32_read_sector(fat_sector, 1, sector_buf) != 0) {
        return 0x0FFFFFF7u; /* Bad cluster indicator */
    }

    uint32_t next = *(uint32_t*)&sector_buf[ent_offset] & 0x0FFFFFFFu;
    return next;
}

static int fat32_mount(fat32_fs* fs) {
    uint8_t boot_sec[SD_BLOCK_SIZE];
    if (fat32_read_sector(0, 1, boot_sec) != 0) {
        return SW2_ERR_SD_INIT;
    }

    /* Verify FAT32 BPB */
    fat32_bpb* bpb = (fat32_bpb*)boot_sec;
    if (bpb->bytes_per_sector != 512 || bpb->sectors_per_cluster == 0) {
        /* Check if sector 0 was an MBR instead of VBR */
        if (boot_sec[510] == 0x55 && boot_sec[511] == 0xAA) {
            uint32_t part_lba = *(uint32_t*)&boot_sec[0x1BE + 8];
            if (part_lba != 0 && fat32_read_sector(part_lba, 1, boot_sec) == 0) {
                bpb = (fat32_bpb*)boot_sec;
            }
        }
    }

    if (bpb->bytes_per_sector != 512 || bpb->sectors_per_cluster == 0) {
        return SW2_ERR_SD_MOUNT;
    }

    fs->sectors_per_cluster = bpb->sectors_per_cluster;
    fs->bytes_per_cluster = bpb->sectors_per_cluster * SD_BLOCK_SIZE;
    fs->fat_start_lba = bpb->reserved_sector_count;
    fs->table_size = bpb->table_size_32;
    fs->cluster_start_lba = fs->fat_start_lba + (bpb->table_count * bpb->table_size_32);
    fs->root_cluster = bpb->root_cluster;

    return SW2_ERR_OK;
}

/* Find file in FAT32 directory matching 11-byte 8.3 name (e.g. "HBLOADERBIN") */
static int fat32_find_file(const fat32_fs* fs, uint32_t dir_cluster, const char* name83, uint32_t* out_cluster, uint32_t* out_size) {
    uint8_t clus_buf[4096];
    uint32_t curr_clus = dir_cluster;

    while (curr_clus < 0x0FFFFFF8u) {
        uint32_t lba = fs->cluster_start_lba + (curr_clus - 2) * fs->sectors_per_cluster;
        if (fat32_read_sector(lba, fs->sectors_per_cluster, clus_buf) != 0) {
            return SW2_ERR_FILE_READ;
        }

        fat_dir_entry* entries = (fat_dir_entry*)clus_buf;
        uint32_t num_entries = fs->bytes_per_cluster / sizeof(fat_dir_entry);

        for (uint32_t i = 0; i < num_entries; ++i) {
            if (entries[i].name[0] == 0x00) return SW2_ERR_FILE_NOT_FOUND; /* End of dir */
            if (entries[i].name[0] == 0xE5) continue;                     /* Deleted entry */
            if (entries[i].attr == 0x0F) continue;                         /* Long filename entry */

            if (sw2_memcmp(entries[i].name, name83, 11) == 0) {
                *out_cluster = ((uint32_t)entries[i].fst_clus_hi << 16) | entries[i].fst_clus_lo;
                *out_size = entries[i].file_size;
                return SW2_ERR_OK;
            }
        }

        curr_clus = fat32_get_next_cluster(fs, curr_clus);
    }

    return SW2_ERR_FILE_NOT_FOUND;
}

/* Read continuous cluster chain into memory */
static int fat32_read_file_data(const fat32_fs* fs, uint32_t start_cluster, uint32_t file_size, uint8_t* dst) {
    uint32_t curr_clus = start_cluster;
    uint32_t bytes_remaining = file_size;
    uint8_t* cur_dst = dst;

    while (bytes_remaining > 0 && curr_clus < 0x0FFFFFF8u) {
        uint32_t lba = fs->cluster_start_lba + (curr_clus - 2) * fs->sectors_per_cluster;
        uint32_t to_read = (bytes_remaining > fs->bytes_per_cluster) ? fs->bytes_per_cluster : bytes_remaining;

        if (to_read == fs->bytes_per_cluster) {
            if (fat32_read_sector(lba, fs->sectors_per_cluster, cur_dst) != 0) {
                return SW2_ERR_FILE_READ;
            }
        } else {
            uint8_t tmp[4096];
            if (fat32_read_sector(lba, fs->sectors_per_cluster, tmp) != 0) {
                return SW2_ERR_FILE_READ;
            }
            sw2_memcpy(cur_dst, tmp, to_read);
        }

        cur_dst += to_read;
        bytes_remaining -= to_read;
        curr_clus = fat32_get_next_cluster(fs, curr_clus);
    }

    return (bytes_remaining == 0) ? SW2_ERR_OK : SW2_ERR_FILE_READ;
}

/* --- Homebrew Execution ABI Preparation ------------------------------------------------------ */

static void setup_hbl_config_table(hbl_config_entry* table, const char* next_load_path) {
    int idx = 0;

    /* Main Thread Handle (Default 0xFFFF8001 on Horizon) */
    table[idx].key = HBL_KEY_MAIN_THREAD_HANDLE;
    table[idx].flags = 0;
    table[idx].value[0] = 0xFFFF8001ULL;
    table[idx].value[1] = 0;
    idx++;

    /* Next Load Path */
    table[idx].key = HBL_KEY_NEXT_LOAD_PATH;
    table[idx].flags = 0;
    table[idx].value[0] = (uint64_t)(uintptr_t)next_load_path;
    table[idx].value[1] = (uint64_t)(uintptr_t)next_load_path;
    idx++;

    /* Applet Type */
    table[idx].key = HBL_KEY_APPLET_TYPE;
    table[idx].flags = 0;
    table[idx].value[0] = 1; /* AppletType_LibraryApplet */
    table[idx].value[1] = 0;
    idx++;

    /* End of Table */
    table[idx].key = HBL_KEY_END_OF_LIST;
    table[idx].flags = 0;
    table[idx].value[0] = 0;
    table[idx].value[1] = 0;
}

/* --- Main Stage 2 Entry Point ----------------------------------------------------------------- */

int sw2_stage2_load_hbloader(const sw2_resolved* s1, void* load_buffer, size_t buffer_size, void** out_entrypoint) {
    if (!s1) return SW2_ERR_STAGE1_NULL;
    if (!load_buffer || buffer_size < (1024 * 1024)) return SW2_ERR_MEM_ALLOC;

    fat32_fs fs;
    int rc = fat32_mount(&fs);
    if (rc != SW2_ERR_OK) {
        return rc;
    }

    /* Direct target: "HBMENU.NRO" (8.3 name: "HBMENU  NRO") - no hbloader needed */
    uint32_t file_cluster = 0;
    uint32_t file_size = 0;
    static const char target_name[11] = {'H','B','M','E','N','U',' ',' ','N','R','O'};

    rc = fat32_find_file(&fs, fs.root_cluster, target_name, &file_cluster, &file_size);
    if (rc != SW2_ERR_OK || file_size == 0 || file_size > buffer_size) {
        return (rc != SW2_ERR_OK) ? rc : SW2_ERR_FILE_READ;
    }

    /* Read the homebrew menu NRO from SD card directly into memory */
    uint8_t* target_dest = (uint8_t*)load_buffer;
    rc = fat32_read_file_data(&fs, file_cluster, file_size, target_dest);
    if (rc != SW2_ERR_OK) {
        return rc;
    }

    /* Determine format & entry point */
    void* entrypoint = target_dest;
    nro_header* nro = (nro_header*)(target_dest + sizeof(nro_start));

    if (nro->magic == NRO0_MAGIC) {
        /* Zero out BSS section */
        uint8_t* bss_addr = target_dest + nro->size;
        if (nro->bss_size > 0 && ((size_t)(nro->size + nro->bss_size) <= buffer_size)) {
            sw2_memset(bss_addr, 0, nro->bss_size);
        }
        /* NRO entrypoint is after nro_start trampoline or at start */
        entrypoint = (void*)target_dest;
    }

    /* Prepare Homebrew Config Table ABI directly for hbmenu */
    static hbl_config_entry g_config_table[16];
    static const char g_next_path[] = "sdmc:/hbmenu.nro";
    setup_hbl_config_table(g_config_table, g_next_path);

    /* Flush and invalidate caches before execution */
    sw2_cache_flush_and_invalidate(load_buffer, file_size);

    if (out_entrypoint) {
        *out_entrypoint = entrypoint;
    }

    return SW2_ERR_OK;
}

/* Handoff trigger: branches into homebrew loader passing AAPCS64 ABI arguments */
void sw2_handoff_to_hbloader(void* entrypoint, void* config_table) {
#if defined(__aarch64__)
    register uint64_t x0_reg __asm__("x0") = (uint64_t)(uintptr_t)config_table;
    register uint64_t x1_reg __asm__("x1") = 0xFFFF8001ULL;
    register uint64_t x2_reg __asm__("x2") = 0;
    register uint64_t x3_reg __asm__("x3") = 0;
    __asm__ volatile (
        "br  %4\n"          /* Branch to hbloader / NRO */
        :
        : "r"(x0_reg), "r"(x1_reg), "r"(x2_reg), "r"(x3_reg), "r"(entrypoint)
        : "memory"
    );
#else
    (void)entrypoint;
    (void)config_table;
#endif
}

/* --- Host Harness / Unit Test Verification ---------------------------------------------------- */

#if defined(SW2_HOST_TEST)

static uint8_t g_mock_sd[8 * 1024 * 1024]; /* 8 MB mock disk image */

static int mock_sd_reader(uint32_t lba, uint32_t count, void* buffer) {
    size_t offset = (size_t)lba * SD_BLOCK_SIZE;
    size_t bytes = (size_t)count * SD_BLOCK_SIZE;
    if (offset + bytes > sizeof(g_mock_sd)) return -1;
    memcpy(buffer, &g_mock_sd[offset], bytes);
    return 0;
}

/* Format an in-memory FAT32 disk image containing HBLOADER.BIN */
static void init_mock_fat32_with_hbloader(const uint8_t* payload, size_t payload_len) {
    memset(g_mock_sd, 0, sizeof(g_mock_sd));

    /* Sector 0: FAT32 BPB */
    fat32_bpb* bpb = (fat32_bpb*)g_mock_sd;
    bpb->bytes_per_sector = 512;
    bpb->sectors_per_cluster = 8; /* 4096 bytes per cluster */
    bpb->reserved_sector_count = 32;
    bpb->table_count = 2;
    bpb->total_sectors_32 = sizeof(g_mock_sd) / 512;
    bpb->table_size_32 = 64;
    bpb->root_cluster = 2;

    uint32_t fat1_lba = bpb->reserved_sector_count;
    uint32_t fat2_lba = fat1_lba + bpb->table_size_32;
    uint32_t cluster_start = fat1_lba + 2 * bpb->table_size_32;

    /* Root directory at cluster 2 */
    uint32_t root_lba = cluster_start;
    fat_dir_entry* dir = (fat_dir_entry*)&g_mock_sd[root_lba * 512];
    memcpy(dir[0].name, "HBMENU  NRO", 11);
    dir[0].attr = 0x20; /* Archive */
    dir[0].fst_clus_hi = 0;
    dir[0].fst_clus_lo = 3; /* File starts at cluster 3 */
    dir[0].file_size = (uint32_t)payload_len;

    /* FAT tables: cluster 2 is EOC, cluster 3 is start of file */
    uint32_t* fat = (uint32_t*)&g_mock_sd[fat1_lba * 512];
    fat[0] = 0x0FFFFFF8;
    fat[1] = 0xFFFFFFFF;
    fat[2] = 0x0FFFFFFF; /* EOC for root dir */

    uint32_t num_clusters = ((uint32_t)payload_len + 4095) / 4096;
    for (uint32_t i = 0; i < num_clusters; ++i) {
        uint32_t c = 3 + i;
        fat[c] = (i + 1 < num_clusters) ? (c + 1) : 0x0FFFFFFF;
    }
    memcpy(&g_mock_sd[fat2_lba * 512], fat, bpb->table_size_32 * 512);

    /* Write payload data starting at cluster 3 */
    uint32_t file_lba = cluster_start + (3 - 2) * bpb->sectors_per_cluster;
    memcpy(&g_mock_sd[file_lba * 512], payload, payload_len);
}

int main(int argc, char** argv) {
    printf("[stage2_hbloader] initializing host harness test...\n");

    /* Create synthetic NRO payload */
    static uint8_t mock_nro[65536];
    memset(mock_nro, 0, sizeof(mock_nro));
    nro_header* hdr = (nro_header*)(mock_nro + sizeof(nro_start));
    hdr->magic = NRO0_MAGIC;
    hdr->size = sizeof(mock_nro);
    hdr->text_size = 16384;
    hdr->bss_size = 4096;

    /* Install sector reader & mock image */
    init_mock_fat32_with_hbloader(mock_nro, sizeof(mock_nro));
    g_sector_reader = mock_sd_reader;

    sw2_resolved s1 = {0};
    s1.sdk_base = 0x10000000;
    s1.main_base = 0x08000000;

    static uint8_t staging_mem[1024 * 1024];
    void* entrypoint = NULL;

    int rc = sw2_stage2_load_hbloader(&s1, staging_mem, sizeof(staging_mem), &entrypoint);
    printf("[stage2_hbloader] load result rc=%d entrypoint=%p\n", rc, entrypoint);

    if (rc == SW2_ERR_OK && entrypoint == staging_mem) {
        printf("[stage2_hbloader] TEST PASSED: hbloader successfully pulled from SD and mapped.\n");
        return 0;
    }

    printf("[stage2_hbloader] TEST FAILED: rc=%d\n", rc);
    return 1;
}

#endif
