// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <assert.h>
#include <err.h>
#include <kernel/cmdline.h>
#include <kernel/vm.h>

/* Checks if a memory limit has been imposed on the system by the boot
 * command line. NO_ERROR indicates a valid limit is being returned,
 * whereas ERR_NOT_SUPPORTED indicates there is no such restriction
 * on the kernel.
 */
mx_status_t get_kernel_memory_limit(uint64_t* limit) {
    uint64_t _limit;

    if (!limit) {
        return ERR_INVALID_ARGS;
    }

    _limit = cmdline_get_uint64("kernel.memory-limit", 0);

    if (_limit == 0) {
        return ERR_NOT_SUPPORTED;
    }

    *limit = _limit;
    return NO_ERROR;
}

/* This will take a contiguous range of memory and return pmm arenas corresponding to the arenas
 * that needed to be carved out due to placement of the kernel, placement of the ramdisk, and any
 * memory limits being imposed upon the system. 'arenas_used' is set to the number of arenas needed
 * to represent the result of the operation, and the arenas themselves are stored in 'arenas'. The
 * size of the arena is subtracted from the value passed in by 'limit'
 */
mx_status_t apply_kernel_memory_limit(uintptr_t range_base, size_t range_size
                                      uintptr_t ramdisk_size, uint priority, pmm_arena_info_t* arenas, size_t arena_cnt,
                                      size_t* arenas_used_, size_t* limit_) {
    size_t arenas_needed = 0;
    size_t limit = limit_;
    uintptr_t range_end = range_base + range_size;

    /* Kernel */
    uintptr_t k_base = KERNEL_LOAD_OFFSET;
    size_t k_size = &_end - k_base;

    /* Ramdisk */
    size_t r_size = 0;
    uintptr_t r_base = platform_get_ramdisk(&r_size);

    if (!arenas || !arenas_used || arena_cnt < 2) {
        return ERR_INVALID_ARGS;
    }

    /* If our limit has been reached this arena can be skipped */
    if (limit == 0) {
        *arenas_used = 0;
        return NO_ERROR;
    }

    /* The entire range fits into memory */
    if (limit <= range_size) {
        *arenas_used_ = 1;
        *limit_ -= range_size;

        arenas[0].base = range_base;
        arenas[0].size = range_size;
        arenas[0].name = "memory";
        arenas[0].priority = 1;
        arenas[0].flags = PMM_ARENA_FLAG_KMAP;

        return NO_ERROR;
    }

    /* This is where things get more complicated. On both x86 and ARM the kernel
     * and ramdisk will exist in the same memory range. On x86 this is the lowmem region below 4GB
     * based on where UEFI's page allocations placed it. For ARM, it depends on the platform's
     * bootrom, but the important detail is that they both should be in the same contiguous block of
     * DRAM. Either way, we know the kernel + bss needs to be included in memory regardless so
     * that's the first priority.
     *
     * If the kernel and ramdisk were in different ranges and the system only held enough memory for
     * each of them then this would need to be a much more complicated and stateful process.
     * Fortunately, that is not yet the case. If that ever changes we will need a smater way to do
     * handle this at a level below this call.
     *
     * TODO: Handle kernel relocation such that it could be after the ramdisk, or placed with a game
     * between the range start and kernel base.
     */
    if (range_base <= k_base && k_base < range_end) {
        pmm_arena_info_t* kernel = &arenas[0];
        pmm_arena_info_t* ramdisk = &arenas[1];

        /* Kernel starts by spanning from the base until next to the ramdisk */
        kernel->base = range_base;
        kernel->size = k_size + (r_base - &_end);

        /* Ramdisk starts at base and continues to end of the range */
        ramdisk->base = r_base;
        ramdisk->size = range_end - r_base;
