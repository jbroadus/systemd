/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#define SLOT_A 0

typedef struct {
        /* Metadata about the structure */
        UINT8 version;              // 0x1
        UINT8 upgrade_pending;      // Set to nonzero value by userspace if boot_efi has changed
        UINT8 boot_count;           // Incremented by bootloader when booting if upgrade_pending
        UINT8 max_boot_count;       // Maximum allowed unsuccessful boot count
        UINT8 active_slot;          // Zero -- a; Nonzero -- b
        UINT8 reserved;

        /* Paths of the unified kernel images */
        CHAR16 a_efi[256];          // L"\\EFI\\Linux\\linux_a.efi"
        CHAR16 b_efi[256];          // L"\\EFI\\Linux\\linux_b.efi"
} ABConfig;

BOOLEAN get_ab_config(EFI_FILE_HANDLE root_dir, ABConfig *config);

BOOLEAN increment_boot_count(EFI_FILE_HANDLE root_dir, ABConfig *config);
BOOLEAN switch_active_slot(EFI_FILE_HANDLE root_dir, ABConfig *config);
