/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

#include "../common/portability_macros.h"

/* Stack marking
 * ref: https://wiki.gentoo.org/wiki/Hardened/GNU_stack_quickstart
 */
#if defined(__ELF__) && defined(__GNUC__)
.section .note.GNU-stack,"",%progbits
#endif

#if ZSTD_ENABLE_ASM_ARM64

#if !(__APPLE__)
/* on Apple platforms ' %%' is used as seperator instead of ';' */
    #define __ENDL__ ;
#else
    #define __ENDL__ %%
#endif

/* Calling convention:
 *
 * x0 contains the first argument: HUF_DecompressAsmArgs*.
 * sp contains the stack pointer.
 * register's [x19, x24] contents are preserved.
 *
 * TODO: Support Windows calling convention.
 */

ZSTD_HIDE_ASM_FUNCTION(HUF_decompress4X1_usingDTable_internal_fast_arm64_loop)
ZSTD_HIDE_ASM_FUNCTION(HUF_decompress4X2_usingDTable_internal_fast_arm64_loop)
ZSTD_HIDE_ASM_FUNCTION(_HUF_decompress4X2_usingDTable_internal_fast_arm64_loop)
ZSTD_HIDE_ASM_FUNCTION(_HUF_decompress4X1_usingDTable_internal_fast_arm64_loop)
.global HUF_decompress4X1_usingDTable_internal_fast_arm64_loop
.global HUF_decompress4X2_usingDTable_internal_fast_arm64_loop
.global _HUF_decompress4X1_usingDTable_internal_fast_arm64_loop
.global _HUF_decompress4X2_usingDTable_internal_fast_arm64_loop
.text

/* Sets up register mappings for clarity. */

#define op0    x2
#define op1    x3
#define op2    x4
#define op3    x5

#define ip0    x6
#define ip1    x7
#define ip2    x8
#define ip3    x9

#define bits0  x10
#define bits1  x11
#define bits2  x12
#define bits3  x13
#define dtable x14
#define olimit x15
#define ilowest x23
#define oend x24
#define oend1 x16
#define oend2 x17
#define oend3 x19

#define var0   x19
#define var1   x1
#define var2   x16
#define var3   x17

/* 32-bit var registers */
#define vard0  w19
#define vard1  w1
#define vard2  w16
#define vard3  w17

/* Calls X(N) for each stream 0, 1, 2, 3. */
#define FOR_EACH_STREAM(X) \
    X(0) __ENDL__                 \
    X(1) __ENDL__                 \
    X(2) __ENDL__                 \
    X(3)

/* Calls X(N, idx) for each stream 0, 1, 2, 3. */
#define FOR_EACH_STREAM_WITH_INDEX(X, idx) \
    X(0, idx) __ENDL__                            \
    X(1, idx) __ENDL__                            \
    X(2, idx) __ENDL__                            \
    X(3, idx)

/* Define both _HUF_* & HUF_* symbols because MacOS
 * C symbols are prefixed with '_' & Linux symbols aren't.
 */
_HUF_decompress4X1_usingDTable_internal_fast_arm64_loop:
HUF_decompress4X1_usingDTable_internal_fast_arm64_loop:
    ZSTD_CET_ENDBRANCH
    /* save callee saved registers. */

    stp x19, x20, [sp, #-48]
    stp x21, x22, [sp, #-32]
    stp x23, x24, [sp, #-16]

    /* Read HUF_DecompressAsmArgs* args from x0 */
    ldp ip0, ip1, [x0]
    ldp ip2, ip3, [x0, #16]
    ldp op0, op1, [x0, #32]
    ldp op2, op3, [x0, #48]
    ldp bits0, bits1, [x0, #64]
    ldp bits2, bits3, [x0, #80]
    ldp dtable, ilowest, [x0, #96]
    ldr oend, [x0, #112]

    mov     x20, #9363
    movk    x20, #37449, lsl 16
    movk    x20, #18724, lsl 32
    movk    x20, #9362, lsl 48

.L_4X1_compute_olimit:
    /* Computes how many iterations we can do safely */

    mov x15, #-3689348814741910324
    movk x15, #52429, lsl 0

    /* x21 = ip0 - ilowest */
    sub x21, ip0, ilowest

    /* x22 = (ip0 - ilowest) / 7 */
    umulh   x22, x21, x20
    sub     x21, x21, x22
    add     x22, x22, x21, lsr #1
    lsr     x22, x22, 2

    /* x21 = oend - op3 */
    sub x21, oend, op3

    /* x15 = (oend - op3) / 5 */
    umulh x15, x21, x15
    lsr x15, x15, 2

    /* x15 = min(x22, x15) */
    cmp     x22, x15
    csel    x15, x22, x15, ls

    cmp x15, #0
    beq .L_4X1_exit

    /* If (ip1 < ip0) go to exit */
    cmp ip0, ip1
    bhi .L_4X1_exit

    /* If (ip2 < ip1) go to exit */
    cmp ip1, ip2
    bhi .L_4X1_exit

    /* If (ip3 < ip2) go to exit */
    cmp ip2, ip3
    bhi .L_4X1_exit

    /* x15 = x15 * 5 */
    add x15, x15, x15, lsl #2

    /* olimit = op3 + x15 */
    add olimit, x15, op3

/* Reads top 11 bits from bits[n]
 * Loads dt[bits[n]] into var[n]
 */
#define GET_NEXT_DELT(n)                        \
    lsr var##n, bits##n, #53 __ENDL__                  \
    ldrh vard##n, [dtable, var##n, lsl #1] __ENDL__

/* var[n] must contain the DTable entry computed with GET_NEXT_DELT
 * Moves var[n] to x21
 * bits[n] <<= var[n] & 63
 * op[n][idx] = x21 >> 8
 */
#define DECODE_FROM_DELT(n, idx)        \
    lsr x21, var##n, #8 __ENDL__               \
    lsl bits##n, bits##n, var##n __ENDL__      \
    strb w21, [op##n, ##idx] __ENDL__

/* Assumes GET_NEXT_DELT has been called.
 * Calls DECODE_FROM_DELT then GET_NEXT_DELT
 */
#define DECODE_AND_GET_NEXT(n, idx) \
    DECODE_FROM_DELT(n, idx) __ENDL__      \
    GET_NEXT_DELT(n)                \

/* // ctz & nbBytes is stored in bits[n]
 * ctz  = CTZ[bits[n]]
 * nbBits  = ctz & 7
 * nbBytes = ctz >> 3
 * op[n]  += 5
 * ip[n]  -= nbBytes
 * // Note: x86-64 is little-endian ==> no bswap
 * bits[n] = MEM_readST(ip[n]) | 1
 * bits[n] <<= nbBits
 */
#define RELOAD_BITS(n)                  \
    rbit bits##n, bits##n __ENDL__             \
    clz bits##n, bits##n __ENDL__              \
    sub ip##n, ip##n, bits##n, lsr #3 __ENDL__ \
    and x22, bits##n, #7 __ENDL__              \
    add op##n, op##n, #5 __ENDL__              \
    ldr bits##n, [ip##n] __ENDL__              \
    orr bits##n, bits##n, #1 __ENDL__          \
    lsl bits##n, bits##n, x22 __ENDL__

    /* Call GET_NEXT_DELT for each stream */
    FOR_EACH_STREAM(GET_NEXT_DELT)

    .p2align 6

.L_4X1_loop_body:
    /* Decode 5 symbols in each of the 4 streams (20 total)
     * Must have called GET_NEXT_DELT for each stream
     */
    FOR_EACH_STREAM_WITH_INDEX(DECODE_AND_GET_NEXT, 0)
    FOR_EACH_STREAM_WITH_INDEX(DECODE_AND_GET_NEXT, 1)
    FOR_EACH_STREAM_WITH_INDEX(DECODE_AND_GET_NEXT, 2)
    FOR_EACH_STREAM_WITH_INDEX(DECODE_AND_GET_NEXT, 3)
    FOR_EACH_STREAM_WITH_INDEX(DECODE_FROM_DELT, 4)

    /* Reload each stream & fetch the next table entry
     * to prepare for the next iteration
     */
    RELOAD_BITS(0)
    GET_NEXT_DELT(0)

    RELOAD_BITS(1)
    GET_NEXT_DELT(1)

    RELOAD_BITS(2)
    GET_NEXT_DELT(2)

    RELOAD_BITS(3)
    GET_NEXT_DELT(3)

    /* If op3 < olimit: continue the loop */
    cmp olimit, op3
    bhi .L_4X1_loop_body

    /* Re-compute olimit */
    b .L_4X1_compute_olimit

#undef GET_NEXT_DELT
#undef DECODE_FROM_DELT
#undef DECODE
#undef RELOAD_BITS
.L_4X1_exit:

    /* Save ip / op / bits */
    stp ip0, ip1, [x0]
    stp ip2, ip3, [x0, #16]
    stp op0, op1, [x0, #32]
    stp op2, op3, [x0, #48]
    stp bits0, bits1, [x0, #64]
    stp bits2, bits3, [x0, #80]

    ldp x19, x20, [sp, #-48]
    ldp x21, x22, [sp, #-32]
    ldp x23, x24, [sp, #-16]

    ret

_HUF_decompress4X2_usingDTable_internal_fast_arm64_loop:
HUF_decompress4X2_usingDTable_internal_fast_arm64_loop:
    ZSTD_CET_ENDBRANCH
    /* save callee saved registers. */

    stp x19, x20, [sp, #-48]
    stp x21, x22, [sp, #-32]
    stp x23, x24, [sp, #-16]

    /* Read HUF_DecompressAsmArgs* args from x0 */
    ldp ip0, ip1, [x0]
    ldp ip2, ip3, [x0, #16]
    ldp op0, op1, [x0, #32]
    ldp op2, op3, [x0, #48]
    ldp bits0, bits1, [x0, #64]
    ldp bits2, bits3, [x0, #80]
    ldp dtable, ilowest, [x0, #96]
    ldr oend, [x0, #112]

    mov oend1, op1
    mov oend2, op2
    mov oend3, op3

    mov     x22, #9363
    movk    x22, #37449, lsl 16
    movk    x22, #18724, lsl 32
    movk    x22, #9362, lsl 48

.L_4X2_compute_olimit:

    /* x21 = ip0 - ilowest */
    sub x21, ip0, ilowest
    sub x1, oend1, op0
    sub x20, oend2, op1

    /* x15 = (ip0 - ilowest) / 7 */
    /* x15 = min(x15, min(oend1 - op0, oend2 - op1, oend3 - op2, oend - op3) / 10) */

    umulh   x15, x21, x22
    sub     x21, x21, x15
    add     x15, x15, x21, lsr #1

    sub x21, oend3, op2

    lsr     x15, x15, 2

    cmp x1, x20
    csel x20, x1, x20, ls

    sub x1, oend, op3

    cmp x21, x20
    csel x20, x21, x20, ls

    mov     x21, -3689348814741910324
    movk    x21, 0xcccd, lsl 0

    cmp x1, x20
    csel x20, x1, x20, ls

    umulh   x21, x20, x21
    lsr     x20, x21, 3

    cmp x15, x20
    csel x20, x15, x20, ls

    /* If x20 == 0 */
    cmp x20, #0
    beq .L_4X2_exit

    /* If (ip1 < ip0) go to exit */
    cmp ip0, ip1
    bhi .L_4X2_exit

    /* If (ip2 < ip1) go to exit */
    cmp ip1, ip2
    bhi .L_4X2_exit

    /* If (ip3 < ip2) go to exit */
    cmp ip2, ip3
    bhi .L_4X2_exit

    /* olimit = op3 + 5 * x20 */
    add x1, x20, x20, lsl #2
    add olimit, op3, x1

#define DECODE(n, idx)               \
    lsr x21, bits##n, #53 __ENDL__          \
    ldr w21, [dtable, x21, lsl #2] __ENDL__ \
    strh w21, [op##n] __ENDL__              \
    lsr w20, w21, #16 __ENDL__              \
    add op##n, op##n, x21, lsr #24 __ENDL__ \
    and x20, x20, #255 __ENDL__             \
    lsl bits##n, bits##n, x20 __ENDL__

#define RELOAD_BITS(n)                  \
    rbit bits##n, bits##n __ENDL__              \
    clz bits##n, bits##n __ENDL__               \
    sub ip##n, ip##n, bits##n, lsr #3 __ENDL__  \
    and x1, bits##n, #7 __ENDL__                \
    ldr bits##n, [ip##n] __ENDL__               \
    orr bits##n, bits##n, #1 __ENDL__           \
    lsl bits##n, bits##n, x1 __ENDL__

    .p2align 6

.L_4X2_loop_body:

    /* Decode 5 symbols from each of the 4 streams (20 symbols total). */
    FOR_EACH_STREAM_WITH_INDEX(DECODE, 0)
    FOR_EACH_STREAM_WITH_INDEX(DECODE, 1)
    FOR_EACH_STREAM_WITH_INDEX(DECODE, 2)
    FOR_EACH_STREAM_WITH_INDEX(DECODE, 3)
    FOR_EACH_STREAM_WITH_INDEX(DECODE, 4)

    FOR_EACH_STREAM(RELOAD_BITS)

    cmp olimit, op3
    bhi .L_4X2_loop_body
    b .L_4X2_compute_olimit

#undef DECODE
#undef RELOAD_BITS
.L_4X2_exit:

    /* Save ip / op / bits */
    stp ip0, ip1, [x0]
    stp ip2, ip3, [x0, #16]
    stp op0, op1, [x0, #32]
    stp op2, op3, [x0, #48]
    stp bits0, bits1, [x0, #64]
    stp bits2, bits3, [x0, #80]

    ldp x19, x20, [sp, #-48]
    ldp x21, x22, [sp, #-32]
    ldp x23, x24, [sp, #-16]

    ret

#endif
