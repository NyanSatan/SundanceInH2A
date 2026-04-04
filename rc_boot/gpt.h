#ifndef GPT_H
#define GPT_H

#include <stdint.h>

typedef
struct __attribute__((packed)) {
    uint8_t signature[8];
#define GPT_MAGIC   "EFI PART"
    uint32_t revision;
    uint32_t hdr_size;
    uint32_t hdr_crc32;
    uint32_t reserved;
    uint64_t hdr_lba;
    uint64_t backup_lba;
    uint64_t first_lba;
    uint64_t last_lba;
    uint8_t  guid[16];
    uint64_t ptab_lba;
    uint32_t ptab_cnt;
    uint32_t ptab_entry_size;
    uint32_t ptab_crc32;
} GPTHeader;

typedef
struct __attribute__((packed)) {
    uint8_t  signature[16];
    uint8_t  guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attributes;
    uint16_t name[0x24];
} GPTPartition;

static
uint8_t GPTHFSSignature[] = {0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC};

#endif
