// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ddk/binding.h>
#include <ddk/device.h>
#include <ddk/driver.h>

#include <magenta/syscalls.h>
#include <magenta/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#define FIFOSIZE 256
#define FIFOMASK (FIFOSIZE - 1)

static struct {
    uint8_t data[FIFOSIZE];
    uint32_t head;
    uint32_t tail;
    mtx_t lock;
} fifo = {
    .lock = MTX_INIT,
};

static mx_status_t fifo_read(uint8_t* out) {
    if (fifo.head == fifo.tail) {
        return -1;
    }
    *out = fifo.data[fifo.tail];
    fifo.tail = (fifo.tail + 1) & FIFOMASK;
    return NO_ERROR;
}

static void fifo_write(uint8_t x) {
    uint32_t next = (fifo.head + 1) & FIFOMASK;
    if (next != fifo.tail) {
        fifo.data[fifo.head] = x;
        fifo.head = next;
    }
}

static int debug_reader(void* arg) {
    mx_device_t* dev = arg;
    uint8_t ch;
    for (;;) {
        if (mx_debug_read(get_root_resource(), (void*)&ch, 1) == 1) {
            mtx_lock(&fifo.lock);
            if (fifo.head == fifo.tail) {
                device_state_set(dev, DEV_STATE_READABLE);
            }
            fifo_write(ch);
            mtx_unlock(&fifo.lock);
        }
    }
    return 0;
}

static ssize_t console_read(mx_device_t* dev, void* buf, size_t count, mx_off_t off) {
    uint8_t* data = buf;
    mtx_lock(&fifo.lock);
    while (count-- > 0) {
        if (fifo_read(data))
            break;
        data++;
    }
    if (fifo.head == fifo.tail) {
        device_state_clr(dev, DEV_STATE_READABLE);
    }
    mtx_unlock(&fifo.lock);
    ssize_t actual = data - (uint8_t*)buf;
    return actual ? actual : (ssize_t)ERR_SHOULD_WAIT;
}

static ssize_t console_write(mx_device_t* dev, const void* buf, size_t count, mx_off_t off) {
    return mx_debug_write(buf, count);
}

static mx_protocol_device_t console_device_proto = {
    .read = console_read,
    .write = console_write,
};

static mx_status_t console_bind(mx_driver_t* drv, mx_device_t* parent, void** cookie) {
    mx_device_t* dev;
    if (device_create(&dev, drv, "console", &console_device_proto) == NO_ERROR) {
        if (device_add(dev, parent) < 0) {
            printf("console: device_add() failed\n");
            free(dev);
        } else {
            thrd_t t;
            thrd_create_with_name(&t, debug_reader, dev, "debug-reader");
        }
    }
    return NO_ERROR;
}

static mx_driver_ops_t console_driver_ops = {
    .version = DRIVER_OPS_VERSION,
    .bind = console_bind,
};

MAGENTA_DRIVER_BEGIN(console, console_driver_ops, "magenta", "0.1", 1)
    BI_MATCH_IF(EQ, BIND_PROTOCOL, MX_PROTOCOL_MISC_PARENT),
MAGENTA_DRIVER_END(console)
