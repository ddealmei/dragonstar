/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef __Hacl_Impl_Blake2_Core_H
#define __Hacl_Impl_Blake2_Core_H
#include "kremlin/internal/types.h"
#include "kremlin/lowstar_endianness.h"
#include <string.h>
#include "lib_intrinsics.h"




#define Hacl_Impl_Blake2_Core_M32 0
#define Hacl_Impl_Blake2_Core_M128 1
#define Hacl_Impl_Blake2_Core_M256 2

typedef uint8_t Hacl_Impl_Blake2_Core_m_spec;

bool Hacl_Impl_Blake2_Core_uu___is_M32(Hacl_Impl_Blake2_Core_m_spec projectee);

bool Hacl_Impl_Blake2_Core_uu___is_M128(Hacl_Impl_Blake2_Core_m_spec projectee);

bool Hacl_Impl_Blake2_Core_uu___is_M256(Hacl_Impl_Blake2_Core_m_spec projectee);


#define __Hacl_Impl_Blake2_Core_H_DEFINED
#endif
