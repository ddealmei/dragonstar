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


#ifndef __Hacl_Hash_Core_SHA2_H
#define __Hacl_Hash_Core_SHA2_H
#include "kremlin/internal/types.h"
#include "kremlin/lowstar_endianness.h"
#include <string.h>
#include "lib_intrinsics.h"


#include "Hacl_Kremlib.h"

void Hacl_Hash_Core_SHA2_init_224(uint32_t *s);

void Hacl_Hash_Core_SHA2_init_256(uint32_t *s);

void Hacl_Hash_Core_SHA2_init_384(uint64_t *s);

void Hacl_Hash_Core_SHA2_init_512(uint64_t *s);

void Hacl_Hash_Core_SHA2_update_224(uint32_t *hash, uint8_t *block);

void Hacl_Hash_Core_SHA2_update_256(uint32_t *hash, uint8_t *block);

void Hacl_Hash_Core_SHA2_update_384(uint64_t *hash, uint8_t *block);

void Hacl_Hash_Core_SHA2_update_512(uint64_t *hash, uint8_t *block);

void Hacl_Hash_Core_SHA2_pad_224(uint64_t len, uint8_t *dst);

void Hacl_Hash_Core_SHA2_pad_256(uint64_t len, uint8_t *dst);

void Hacl_Hash_Core_SHA2_pad_384(uint128_t len, uint8_t *dst);

void Hacl_Hash_Core_SHA2_pad_512(uint128_t len, uint8_t *dst);

void Hacl_Hash_Core_SHA2_finish_224(uint32_t *s, uint8_t *dst);

void Hacl_Hash_Core_SHA2_finish_256(uint32_t *s, uint8_t *dst);

void Hacl_Hash_Core_SHA2_finish_384(uint64_t *s, uint8_t *dst);

void Hacl_Hash_Core_SHA2_finish_512(uint64_t *s, uint8_t *dst);


#define __Hacl_Hash_Core_SHA2_H_DEFINED
#endif
