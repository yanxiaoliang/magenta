// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#ifndef ASSEMBLY
#include <magenta/compiler.h>

__BEGIN_CDECLS

extern void mexec_asm(void);
extern void mexec_asm_end(void);

__END_CDECLS

#endif // ASSEMBLY