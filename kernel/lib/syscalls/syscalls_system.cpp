// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <arch/arch_ops.h>
#include <arch/mp.h>
#include <kernel/mp.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <kernel/vm/vm_aspace.h>
#include <magenta/syscalls_system.h>
#include <magenta/types.h>
#include <platform.h>
#include <debug.h>
#include <string.h>
#include <magenta/process_dispatcher.h>
#include <magenta/vm_object_dispatcher.h>

#include <dev/interrupt.h>
#include <dev/bcm28xx.h>

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

typedef void (*memmove_asm_f)(void* dest, void* source, size_t len);

// TODO(gkalsi); assert on the size and offsets of the members of this struct.
typedef struct __PACKED {
    void* dst;
    void* src;
    size_t len;
} memmov_ops_t;

typedef void (*mexec_asm_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                               uint64_t arg3, memmov_ops_t* ops,
                               void* new_kernel_addr);



/* Returns the cpuid of the boot cpu.
 *
 * The boot cpu is the cpu responsible for
 * booting the system in start.S, secondary cpus are brought up afterwards.
 * For now we assume that cpuid=0 is the boot cpu but this may change for some
 * SOCs in the future.
 */
static uint get_boot_cpu_id(void) {
    return 0;
}

/* Allocates a page of memory that has the same physical and virtual addresses.
 */ 
static mx_status_t identity_page_allocate(void** result_addr) {
    status_t result;

    // Start by obtaining an unused physical page. This address will eventually
    // be the physical/virtual address of our identity mapped page.
    paddr_t pa;
    pmm_alloc_page(0, &pa);

    // The kernel address space may be in high memory which cannot be identity
    // mapped since all Kernel Virtual Addresses might be out of range of the
    // physical address space. For this reason, we need to make a new address
    // space.
    vmm_aspace_t *identity_aspace;
    result = vmm_create_aspace(&identity_aspace, "mexec identity", 
                               VMM_ASPACE_TYPE_LOW_KERNEL);
    if (result != NO_ERROR)
        return result;

    // Create a new allocation in the new address space that identity maps the
    // target page.
    const uint perm_flags_rwx = ARCH_MMU_FLAG_PERM_READ  | 
                                ARCH_MMU_FLAG_PERM_WRITE | 
                                ARCH_MMU_FLAG_PERM_EXECUTE;
    void* identity_address = (void*)pa;
    result = vmm_alloc_physical(identity_aspace, "identity_mapping", PAGE_SIZE,
                                &identity_address, 0, 0, pa,
                                VMM_FLAG_VALLOC_SPECIFIC, perm_flags_rwx);
    if (result != NO_ERROR)
        return result;

    vmm_set_active_aspace(identity_aspace);

    *result_addr = identity_address;

    return NO_ERROR;
}

/* Migrates the current thread to the CPU identified by target_cpuid. */
static void thread_migrate_cpu(const uint target_cpuid) {
    thread_t *self = get_current_thread();
    const uint old_cpu_id = thread_last_cpu(self);
    printf("currently on %u, migrating to %u\n", old_cpu_id, target_cpuid);

    thread_set_pinned_cpu(self, target_cpuid);

    // Ask the target cpu to reschedule.
    mp_reschedule(MP_CPU_ALL, 0);

    // When we return from this call, we should have migrated to the target cpu
    thread_yield();

    arch_disable_ints();

    // Make sure that we have actually migrated.
    const uint current_cpu_id = thread_last_cpu(self);
    DEBUG_ASSERT(current_cpu_id == target_cpuid);

    printf("previously on %u, migrated to %u\n", old_cpu_id, current_cpu_id);
}

// Parks a cpu.
static int park_cpu_thread(void* arg) {

    DEBUG_ASSERT(((uintptr_t)arg & 0xffffffff00000000) == 0);
    uint32_t cpu_id = (uint32_t)((uintptr_t)arg & 0xffffffff);

    // From hereon in, this thread will always be assigned to the pinned cpu.
    thread_migrate_cpu(cpu_id);

    printf("parking cpuid = %u\n", cpu_id);

    // Take the current cpu offline.
    // mp_set_curr_cpu_online(false);

    arch_disable_ints();

    // This method will not return because the target cpu has halted.
    platform_halt_cpu();

    return -1;
}

/* Takes all the pages in a VMO and creates a copy of them where all the pages
 * occupy a physically contiguous region of physical memory.
 */
static mx_status_t vmo_coalesce_pages(mx_handle_t vmo_hdl, paddr_t* addr, size_t* size) {
    DEBUG_ASSERT(addr);
    if (!addr) return ERR_INVALID_ARGS;

    DEBUG_ASSERT(size);
    if (!size) return ERR_INVALID_ARGS;

    // TODO(gkalsi): Validate vmo_hdl.

    // XXX(gkalsi): This is potentially a bug because we removed the previous
    // thread's aspace so we might not be able to get its process dispatcher
    auto up = ProcessDispatcher::GetCurrent();
    mxtl::RefPtr<VmObjectDispatcher> vmo_dispatcher;
    mx_status_t st = 
        up->GetDispatcherWithRights(vmo_hdl, MX_RIGHT_READ, &vmo_dispatcher);
    if (st != NO_ERROR)
        return st;

    mxtl::RefPtr<VmObject> vmo = vmo_dispatcher->vmo();

    const size_t num_pages = vmo->AllocatedPages();

    paddr_t base_addr;
    const size_t allocated = pmm_alloc_contiguous(num_pages, PMM_ALLOC_FLAG_ANY,
                                                  0, &base_addr, nullptr);
    if (allocated < num_pages)
        return ERR_NO_MEMORY;

    for (size_t page_offset = 0; page_offset < num_pages; ++page_offset) {
        const off_t byte_offset = page_offset * PAGE_SIZE;

        const paddr_t page_addr = base_addr + byte_offset;

        void* virtual_addr = paddr_to_kvaddr(page_addr);
        
        size_t bytes_read;
        st = vmo->Read(virtual_addr, byte_offset, PAGE_SIZE, &bytes_read);
        if (st != NO_ERROR || bytes_read != PAGE_SIZE) {
            printf("Vmo Read returned %d bytes read = %lu\n", st, bytes_read);
            return ERR_INTERNAL;
        }

        vmo->CleanInvalidateCache(byte_offset, PAGE_SIZE);
        arch_clean_invalidate_cache_range((addr_t)virtual_addr, PAGE_SIZE);
    }

    *size = (num_pages * PAGE_SIZE);
    *addr = base_addr;

    printf("mexec: copied new kernel to paddr = %" PRIxPTR", "
           "length = %" PRIu64 "\n", *addr, *size);

    return NO_ERROR;
}

mx_status_t sys_system_mexec(mx_handle_t kernel_vmo, 
                             mx_handle_t bootimage_vmo) {
    mx_status_t result;

    printf("entering sys_system_mexec\n");

    // We assume that when the system starts, only one CPU is running. We denote
    // this as the boot CPU.
    // We want to make sure that this is the CPU that eventually branches into
    // the new kernel so we attempt to migrate this thread to that cpu.
    const uint boot_cpu_id = get_boot_cpu_id();
    thread_migrate_cpu(boot_cpu_id);

    printf("migrated to boot cpu\n");

    void* id_page_addr;
    result = identity_page_allocate(&id_page_addr);
    if (result != NO_ERROR) {
        printf("mx_system_mexec failed to allocate identity page, "
               "retcode = %d\n", result);
        return result;
    }

    printf("Identity page is mapped at %p\n", id_page_addr);

    // Create one thread per core to park each core.
    thread_t** park_thread =
        (thread_t**)calloc(arch_max_num_cpus(), sizeof(*park_thread));
    for (uint i = 0; i < arch_max_num_cpus(); i++) {
        // The boot cpu is going to be performing the remainder of the mexec
        // for us so we don't want to park that one.
        if (i == get_boot_cpu_id()) {
            continue;
        }

        char park_thread_name[20];
        snprintf(park_thread_name, sizeof(park_thread_name), "park %u", i);
        park_thread[i] = thread_create(park_thread_name, park_cpu_thread,
                                       (void*)(uintptr_t)i, DEFAULT_PRIORITY,
                                       DEFAULT_STACK_SIZE);
        thread_resume(park_thread[i]);
    }

    // Wait for all the cores to signal shutdown.
    // volatile uintptr_t *spin_table = (volatile uintptr_t *)(KERNEL_ASPACE_BASE + 0xd8);
    // for (int i = 0; i < 4; i++) {
    //     do {
    //         arch_invalidate_cache_range((addr_t)spin_table, 4 * 8);
    //         printf("Spin Table %d = %p\n", i, (void*)spin_table[i]);
    //     } while (spin_table[i]);
    // }

    thread_sleep_relative(LK_SEC(1));

    for (uint i = 0; i < arch_max_num_cpus(); i++) {
        if (i == get_boot_cpu_id()) {
            continue;
        }
        // thread_join(park_thread[i], NULL, INFINITE_TIME);
        // thread_detach(park_thread[i]);
    }

    printf("cpu0 finished migrating all threads\n");

    // XXX(gkalsi): We need to wait for the secondary cores to shutdown before
    // we proceed but there's no way for us to detect that they've finished
    // so we sleep for a bit.
    // for (int i = 0; i < 100; i++) {
    //     printf("sleepint for 10s\n");
    //     thread_sleep(LK_SEC(10));
    //     thread_yield();
    // }
    thread_sleep_relative(LK_SEC(1));

    // We're going to copy this into our identity page, make sure it's not
    // longer than a single page.
    size_t mexec_asm_length = (uintptr_t)mexec_asm_end - (uintptr_t)mexec_asm;
    DEBUG_ASSERT(mexec_asm_length < PAGE_SIZE);

    memcpy(id_page_addr, (const void*)mexec_asm, mexec_asm_length);
    arch_sync_cache_range((addr_t)id_page_addr, mexec_asm_length);

    printf("CPU0 disabling ints\n");
    arch_disable_ints();

    paddr_t new_kernel_addr;
    size_t new_kernel_len;
    result = vmo_coalesce_pages(kernel_vmo, &new_kernel_addr, &new_kernel_len);
    if (result != NO_ERROR) {
        printf("Failed to coalesce vmo kernel pages, retcode = %d\n", result);
        return result;
    }

    paddr_t new_bootimage_addr;
    size_t new_bootimage_len;
    result = vmo_coalesce_pages(bootimage_vmo, &new_bootimage_addr, &new_bootimage_len);
    if (result != NO_ERROR) {
        printf("Failed to coalesce vmo bootimage pages ,retcode = %d\n", result);
        return result;
    }

    // Wait for uart to flush out before taking over.
    // thread_sleep(1000);

    // memset(args_page_addr, 0, PAGE_SIZE);
    uintptr_t ops_ptr = ((((uintptr_t)id_page_addr) + mexec_asm_length + 8) | 0x7) + 1;
    memmov_ops_t* ops = (memmov_ops_t*)(ops_ptr);

    // TODO(gkalsi): This line makes no sense. We should be making sure that all
    // the ops fit into a page.
    DEBUG_ASSERT(sizeof(ops) < PAGE_SIZE);

    // TODO(gkalsi): Make sure the order that these are copied doesn't permit
    // one to be trampled by the other.
    // Op to move the new kernel into place.
    ops[0].src = (void*)new_kernel_addr;
    ops[0].dst = (void*)0x00080000;
    ops[0].len = new_kernel_len;

    // Op to move the new bootimage into place.
    // void* dst_addr = (void*)(0x00080000 + new_kernel_len + 0x1000000);
    void* dst_addr = (void*)0x7d53000;
    ops[1].src = (void*)new_bootimage_addr;
    ops[1].dst = dst_addr;
    ops[1].len = new_bootimage_len;

    // Null terminated list.
    ops[2] = { 0, 0, 0 };

    arch_sync_cache_range((addr_t)id_page_addr, PAGE_SIZE);
    arch_clean_cache_range((addr_t)id_page_addr, PAGE_SIZE);

    printf("Ops pointer located at %p\n", ops);

    memmov_ops_t* dbg_ops = ops;
    while (dbg_ops->src || dbg_ops->dst || dbg_ops->len) {
        printf("Moving %lu bytes from %p to %p\n", dbg_ops->len, dbg_ops->src, dbg_ops->dst);
        dbg_ops += 1;
    }

    printf("masking timer interrupt\n");
    arch_disable_ints();
    shutdown_interrupts();
    printf("Entering mexec_assembly\n");

    mp_set_curr_cpu_active(false);
    mp_set_curr_cpu_online(false);

    mexec_asm_func mexec_assembly = (mexec_asm_func)id_page_addr;
    mexec_assembly((uintptr_t)dst_addr, 0, 0, 0, ops, (void*)0x00080000);

    printf("mx_system_mexec success\n");

    return NO_ERROR;
}