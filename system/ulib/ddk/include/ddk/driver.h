// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <magenta/types.h>
#include <magenta/listnode.h>
#include <magenta/compiler.h>
#include <stdint.h>

__BEGIN_CDECLS;

typedef struct mx_device mx_device_t;
typedef struct mx_protocol_device mx_protocol_device_t;

typedef struct mx_driver mx_driver_t;
typedef struct mx_bind_inst mx_bind_inst_t;
typedef struct mx_driver_binding mx_driver_binding_t;

// echo -n "mx_driver_ops_v0.5" | sha256sum | cut -c1-16
#define DRIVER_OPS_VERSION 0x2b3490fa40d9f452

typedef struct mx_driver_ops {
    uint64_t version;   // DRIVER_OPS_VERSION

    // Opportunity to do on-load work.
    // Called ony once, before any other ops are called.
    mx_status_t (*init)(mx_driver_t* driver);

    // Requests that the driver bind to the provided device,
    // initialize it, and publish and children.
    // On success, the cookie is remembered and passed back on unbind.
    mx_status_t (*bind)(mx_driver_t* driver, mx_device_t* device, void** cookie);

    // Notifies driver that the device which the driver bound to
    // is being removed.  Called after the unbind() op of any devices
    // that are children of that device.
    void (*unbind)(mx_driver_t* driver, mx_device_t* device, void* cookie);

    // Only provided by bus manager drivers, create() is invoked to
    // instantiate a bus device instance in a new device host process
    mx_status_t (*create)(mx_driver_t* driver,
                          const char* name, const char* args,
                          mx_handle_t resource, mx_device_t** out);

    // Last call before driver is unloaded.
    mx_status_t (*release)(mx_driver_t* driver);
} mx_driver_ops_t;

struct mx_driver {
    const char* name;

    mx_driver_ops_t* ops;

    uint32_t flags;

#if !DEVHOST_V2
    struct list_node node;

    const mx_bind_inst_t* binding;
    uint32_t binding_size;
    // binding instructions
#endif
};

// Device Manager API
mx_status_t device_create(mx_device_t** device, mx_driver_t* driver,
                          const char* name, mx_protocol_device_t* ops);
void device_init(mx_device_t* device, mx_driver_t* driver,
                 const char* name, mx_protocol_device_t* ops);
// Devices are created or (if embedded in a driver-specific structure)
// initialized with the above functions.  The mx_device_t will be completely
// written during initialization, and after initialization and before calling
// device_add() they driver may only modify the protocol_id and protocol_ops
// fields of the mx_device_t.

mx_status_t device_add(mx_device_t* device, mx_device_t* parent);
mx_status_t device_add_etc(mx_device_t* device, mx_device_t* parent,
                           const char* businfo, mx_handle_t resource);
mx_status_t device_add_instance(mx_device_t* device, mx_device_t* parent);
mx_status_t device_remove(mx_device_t* device);
mx_status_t device_rebind(mx_device_t* device);

// These are only for the use of core platform drivers and may return
// NULL for non-approved callers.
mx_device_t* driver_get_root_device(void);
mx_device_t* driver_get_misc_device(void);

// Devices are bindable by drivers by default.
// This can be used to prevent a device from being bound by a driver
void device_set_bindable(mx_device_t* dev, bool bindable);

void driver_unbind(mx_driver_t* driver, mx_device_t* dev);

#define ROUNDUP(a, b)   (((a) + ((b)-1)) & ~((b)-1))
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#define ALIGN(a, b) ROUNDUP(a, b)

// temporary accessor for root resource handle
mx_handle_t get_root_resource(void);

mx_status_t load_firmware(mx_driver_t* driver, const char* path,
                          mx_handle_t* fw, size_t* size);
// Drivers may need to load firmware for a device, typically during the call to
// bind the device. The devmgr will look for the firmware at the given path
// relative to system-defined locations for device firmware. The file will be
// loaded into a vmo pointed to by fw. The actual size of the firmware will be
// returned in size.

// panic is for handling non-recoverable, non-reportable fatal
// errors in a way that will get logged.  Right now this just
// does a bogus write to unmapped memory.
static inline void panic(void) {
    for (;;) {
        *((int*) 0xdead) = 1;
    }
}

// Protocol Identifiers
#define DDK_PROTOCOL_DEF(tag, val, name, flags) MX_PROTOCOL_##tag = val,
enum {
#include <ddk/protodefs.h>
};

__END_CDECLS;
