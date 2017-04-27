// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ddk/binding.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <magenta/device/sysinfo.h>
#include <magenta/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


mx_handle_t get_sysinfo_job_root(void);

static ssize_t sysinfo_ioctl(mx_device_t* dev, uint32_t op, const void* cmd, size_t cmdlen,
                             void* reply, size_t max) {
    switch (op) {
    case IOCTL_SYSINFO_GET_ROOT_JOB: {
        if ((cmdlen != 0) || (max < sizeof(mx_handle_t))) {
            return ERR_INVALID_ARGS;
        }
        mx_handle_t h = get_sysinfo_job_root();
        if (h == MX_HANDLE_INVALID) {
            return ERR_NOT_SUPPORTED;
        } else {
            memcpy(reply, &h, sizeof(mx_handle_t));
            return sizeof(mx_handle_t);
        }
    }
    case IOCTL_SYSINFO_GET_ROOT_RESOURCE: {
        if ((cmdlen != 0) || (max < sizeof(mx_handle_t))) {
            return ERR_INVALID_ARGS;
        }
        mx_handle_t h = get_root_resource();
        if (h == MX_HANDLE_INVALID) {
            return ERR_NOT_SUPPORTED;
        }
        mx_status_t status = mx_handle_duplicate(h, MX_RIGHT_ENUMERATE | MX_RIGHT_TRANSFER, &h);
        if (status < 0) {
            return status;
        }
        memcpy(reply, &h, sizeof(mx_handle_t));
        return sizeof(mx_handle_t);
    }
    default:
        return ERR_INVALID_ARGS;
    }
}

static mx_protocol_device_t sysinfo_ops = {
    .ioctl = sysinfo_ioctl,
};

// implement driver object:

mx_status_t sysinfo_init(mx_driver_t* driver) {
    mx_device_t* dev;
    if (device_create(&dev, driver, "sysinfo", &sysinfo_ops) == NO_ERROR) {
        if (device_add(dev, driver_get_misc_device()) < 0) {
            free(dev);
        }
    }
    return NO_ERROR;
}

static mx_driver_ops_t sysinfo_driver_ops = {
    .version = DRIVER_OPS_VERSION,
    .init = sysinfo_init,
};

MAGENTA_DRIVER_BEGIN(sysinfo, sysinfo_driver_ops, "magenta", "0.1", 0)
MAGENTA_DRIVER_END(sysinfo)
