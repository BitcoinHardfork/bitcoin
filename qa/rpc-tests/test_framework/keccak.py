# Keccak implementation.
# ==========================(LICENSE BEGIN)============================
#
# Copyright (c) 2007-2010  Projet RNRT SAPHIR
# Copyright (c) 2017 The Bitcoin Core developers
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ===========================(LICENSE END)=============================
#
# @author   Thomas Pornin <thomas.pornin@cryptolog.com>
# (Ported to Python by Luke Dashjr)
#

import struct

def SPH_T64(x):
    return x & 0xFFFFFFFFFFFFFFFF

def SPH_ROTL64(x, n):
    return SPH_T64((x << n) | (x >> (64 - n)))

RC = (
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008
)

def TH_ELT(c0, c1, c2, c3, c4, d0, d1, d2, d3, d4):
    tt0 = d0 ^ d1
    tt1 = d2 ^ d3
    tt0 = tt0 ^ d4
    tt0 = tt0 ^ tt1
    tt0 = SPH_ROTL64(tt0, 1)
    tt2 = c0 ^ c1
    tt3 = c2 ^ c3
    tt0 = tt0 ^ c4
    tt2 = tt2 ^ tt3
    return tt0 ^ tt2

def THETA(b):
    t0 = TH_ELT(b[40], b[41], b[42], b[43], b[44], b[10], b[11], b[12], b[13], b[14])
    t1 = TH_ELT(b[0], b[1], b[2], b[3], b[4], b[20], b[21], b[22], b[23], b[24])
    t2 = TH_ELT(b[10], b[11], b[12], b[13], b[14], b[30], b[31], b[32], b[33], b[34])
    t3 = TH_ELT(b[20], b[21], b[22], b[23], b[24], b[40], b[41], b[42], b[43], b[44])
    t4 = TH_ELT(b[30], b[31], b[32], b[33], b[34], b[0], b[1], b[2], b[3], b[4])
    b[0] = b[0] ^ t0
    b[1] = b[1] ^ t0
    b[2] = b[2] ^ t0
    b[3] = b[3] ^ t0
    b[4] = b[4] ^ t0
    b[10] = b[10] ^ t1
    b[11] = b[11] ^ t1
    b[12] = b[12] ^ t1
    b[13] = b[13] ^ t1
    b[14] = b[14] ^ t1
    b[20] = b[20] ^ t2
    b[21] = b[21] ^ t2
    b[22] = b[22] ^ t2
    b[23] = b[23] ^ t2
    b[24] = b[24] ^ t2
    b[30] = b[30] ^ t3
    b[31] = b[31] ^ t3
    b[32] = b[32] ^ t3
    b[33] = b[33] ^ t3
    b[34] = b[34] ^ t3
    b[40] = b[40] ^ t4
    b[41] = b[41] ^ t4
    b[42] = b[42] ^ t4
    b[43] = b[43] ^ t4
    b[44] = b[44] ^ t4

def RHO(b):
    # b[0] = SPH_ROTL64(b[0],  0)
    b[1] = SPH_ROTL64(b[1], 36)
    b[2] = SPH_ROTL64(b[2],  3)
    b[3] = SPH_ROTL64(b[3], 41)
    b[4] = SPH_ROTL64(b[4], 18)
    b[10] = SPH_ROTL64(b[10],  1)
    b[11] = SPH_ROTL64(b[11], 44)
    b[12] = SPH_ROTL64(b[12], 10)
    b[13] = SPH_ROTL64(b[13], 45)
    b[14] = SPH_ROTL64(b[14],  2)
    b[20] = SPH_ROTL64(b[20], 62)
    b[21] = SPH_ROTL64(b[21],  6)
    b[22] = SPH_ROTL64(b[22], 43)
    b[23] = SPH_ROTL64(b[23], 15)
    b[24] = SPH_ROTL64(b[24], 61)
    b[30] = SPH_ROTL64(b[30], 28)
    b[31] = SPH_ROTL64(b[31], 55)
    b[32] = SPH_ROTL64(b[32], 25)
    b[33] = SPH_ROTL64(b[33], 21)
    b[34] = SPH_ROTL64(b[34], 56)
    b[40] = SPH_ROTL64(b[40], 27)
    b[41] = SPH_ROTL64(b[41], 20)
    b[42] = SPH_ROTL64(b[42], 39)
    b[43] = SPH_ROTL64(b[43],  8)
    b[44] = SPH_ROTL64(b[44], 14)

#
# The KHI macro integrates the "lane complement" optimization. On input,
# some words are complemented:
#    self.wide[ 0] self.wide[ 5] self.wide[10] self.wide[20] self.wide[16] self.wide[ 2] self.wide[ 7] self.wide[12] self.wide[ 3] self.wide[18] self.wide[23] self.wide[19]
# On output, the following words are complemented:
#    self.wide[20] self.wide[ 1] self.wide[ 2] self.wide[12] self.wide[17] self.wide[ 8]
#
# The (implicit) permutation and the theta expansion will bring back
# the input mask for the next round.
#

def KHI_XO(a, b, c):
    kt = b | c
    return a ^ kt

def KHI_XA(a, b, c):
    kt = b & c
    return a ^ kt

def KHI(b):
    bnn = SPH_T64(~b[20])
    c0 = KHI_XO(b[0], b[10], b[20])
    c1 = KHI_XO(b[10], bnn, b[30])
    c2 = KHI_XA(b[20], b[30], b[40])
    c3 = KHI_XO(b[30], b[40], b[0])
    c4 = KHI_XA(b[40], b[0], b[10])
    b[0] = c0
    b[10] = c1
    b[20] = c2
    b[30] = c3
    b[40] = c4
    bnn = SPH_T64(~b[41])
    c0 = KHI_XO(b[1], b[11], b[21])
    c1 = KHI_XA(b[11], b[21], b[31])
    c2 = KHI_XO(b[21], b[31], bnn)
    c3 = KHI_XO(b[31], b[41], b[1])
    c4 = KHI_XA(b[41], b[1], b[11])
    b[1] = c0
    b[11] = c1
    b[21] = c2
    b[31] = c3
    b[41] = c4
    bnn = SPH_T64(~b[32])
    c0 = KHI_XO(b[2], b[12], b[22])
    c1 = KHI_XA(b[12], b[22], b[32])
    c2 = KHI_XA(b[22], bnn, b[42])
    c3 = KHI_XO(bnn, b[42], b[2])
    c4 = KHI_XA(b[42], b[2], b[12])
    b[2] = c0
    b[12] = c1
    b[22] = c2
    b[32] = c3
    b[42] = c4
    bnn = SPH_T64(~b[33])
    c0 = KHI_XA(b[3], b[13], b[23])
    c1 = KHI_XO(b[13], b[23], b[33])
    c2 = KHI_XO(b[23], bnn, b[43])
    c3 = KHI_XA(bnn, b[43], b[3])
    c4 = KHI_XO(b[43], b[3], b[13])
    b[3] = c0
    b[13] = c1
    b[23] = c2
    b[33] = c3
    b[43] = c4
    bnn = SPH_T64(~b[14])
    c0 = KHI_XA(b[4], bnn, b[24])
    c1 = KHI_XO(bnn, b[24], b[34])
    c2 = KHI_XA(b[24], b[34], b[44])
    c3 = KHI_XO(b[34], b[44], b[4])
    c4 = KHI_XA(b[44], b[4], b[14])
    b[4] = c0
    b[14] = c1
    b[24] = c2
    b[34] = c3
    b[44] = c4


class P:
    seqmap = {}

    def __init__(self, arr, seq):
        self.arr = arr
        self.seq = seq

    def __getitem__(self, n):
        return self.arr[self.seq[self.seqmap[n]]]

    def __setitem__(self, n, val):
        self.arr[self.seq[self.seqmap[n]]] = val

def _setup_P_seqmap():
    i = 0
    for n in (0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 20, 21, 22, 23, 24, 30, 31, 32, 33, 34, 40, 41, 42, 43, 44):
        P.seqmap[n] = i
        i += 1
_setup_P_seqmap()

Pn  = (
    (0, 5, 10, 15, 20, 1, 6, 11, 16, 21, 2, 7, 12, 17, 22, 3, 8, 13, 18, 23, 4, 9, 14, 19, 24),
    (0, 3, 1, 4, 2, 6, 9, 7, 5, 8, 12, 10, 13, 11, 14, 18, 16, 19, 17, 15, 24, 22, 20, 23, 21),
    (0, 18, 6, 24, 12, 9, 22, 10, 3, 16, 13, 1, 19, 7, 20, 17, 5, 23, 11, 4, 21, 14, 2, 15, 8),
    (0, 17, 9, 21, 13, 22, 14, 1, 18, 5, 19, 6, 23, 10, 2, 11, 3, 15, 7, 24, 8, 20, 12, 4, 16),
    (0, 11, 22, 8, 19, 14, 20, 6, 17, 3, 23, 9, 15, 1, 12, 7, 18, 4, 10, 21, 16, 2, 13, 24, 5),
    (0, 7, 14, 16, 23, 20, 2, 9, 11, 18, 15, 22, 4, 6, 13, 10, 17, 24, 1, 8, 5, 12, 19, 21, 3),
    (0, 10, 20, 5, 15, 2, 12, 22, 7, 17, 4, 14, 24, 9, 19, 1, 11, 21, 6, 16, 3, 13, 23, 8, 18),
    (0, 1, 2, 3, 4, 12, 13, 14, 10, 11, 24, 20, 21, 22, 23, 6, 7, 8, 9, 5, 18, 19, 15, 16, 17),
    (0, 6, 12, 18, 24, 13, 19, 20, 1, 7, 21, 2, 8, 14, 15, 9, 10, 16, 22, 3, 17, 23, 4, 5, 11),
    (0, 9, 13, 17, 21, 19, 23, 2, 6, 10, 8, 12, 16, 20, 4, 22, 1, 5, 14, 18, 11, 15, 24, 3, 7),
    (0, 22, 19, 11, 8, 23, 15, 12, 9, 1, 16, 13, 5, 2, 24, 14, 6, 3, 20, 17, 7, 4, 21, 18, 10),
    (0, 14, 23, 7, 16, 15, 4, 13, 22, 6, 5, 19, 3, 12, 21, 20, 9, 18, 2, 11, 10, 24, 8, 17, 1),
    (0, 20, 15, 10, 5, 4, 24, 19, 14, 9, 3, 23, 18, 13, 8, 2, 22, 17, 12, 7, 1, 21, 16, 11, 6),
    (0, 2, 4, 1, 3, 24, 21, 23, 20, 22, 18, 15, 17, 19, 16, 12, 14, 11, 13, 10, 6, 8, 5, 7, 9),
    (0, 12, 24, 6, 18, 21, 8, 15, 2, 14, 17, 4, 11, 23, 5, 13, 20, 7, 19, 1, 9, 16, 3, 10, 22),
    (0, 13, 21, 9, 17, 8, 16, 4, 12, 20, 11, 24, 7, 15, 3, 19, 2, 10, 23, 6, 22, 5, 18, 1, 14),
    (0, 19, 8, 22, 11, 16, 5, 24, 13, 2, 7, 21, 10, 4, 18, 23, 12, 1, 15, 9, 14, 3, 17, 6, 20),
    (0, 23, 16, 14, 7, 5, 3, 21, 19, 12, 10, 8, 1, 24, 17, 15, 13, 6, 4, 22, 20, 18, 11, 9, 2),
    (0, 15, 5, 20, 10, 3, 18, 8, 23, 13, 1, 16, 6, 21, 11, 4, 19, 9, 24, 14, 2, 17, 7, 22, 12),
    (0, 4, 3, 2, 1, 18, 17, 16, 15, 19, 6, 5, 9, 8, 7, 24, 23, 22, 21, 20, 12, 11, 10, 14, 13),
    (0, 24, 18, 12, 6, 17, 11, 5, 4, 23, 9, 3, 22, 16, 10, 21, 15, 14, 8, 2, 13, 7, 1, 20, 19),
    (0, 21, 17, 13, 9, 11, 7, 3, 24, 15, 22, 18, 14, 5, 1, 8, 4, 20, 16, 12, 19, 10, 6, 2, 23),
    (0, 8, 11, 19, 22, 7, 10, 18, 21, 4, 14, 17, 20, 3, 6, 16, 24, 2, 5, 13, 23, 1, 9, 12, 15),
    (0, 16, 7, 23, 14, 10, 1, 17, 8, 24, 20, 11, 2, 18, 9, 5, 21, 12, 3, 19, 15, 6, 22, 13, 4),
)

def P1_TO_P0(wide):
    t = wide[ 5]
    wide[ 5] = wide[ 3]
    wide[ 3] = wide[18]
    wide[18] = wide[17]
    wide[17] = wide[11]
    wide[11] = wide[ 7]
    wide[ 7] = wide[10]
    wide[10] = wide[ 1]
    wide[ 1] = wide[ 6]
    wide[ 6] = wide[ 9]
    wide[ 9] = wide[22]
    wide[22] = wide[14]
    wide[14] = wide[20]
    wide[20] = wide[ 2]
    wide[ 2] = wide[12]
    wide[12] = wide[13]
    wide[13] = wide[19]
    wide[19] = wide[23]
    wide[23] = wide[15]
    wide[15] = wide[ 4]
    wide[ 4] = wide[24]
    wide[24] = wide[21]
    wide[21] = wide[ 8]
    wide[ 8] = wide[16]
    wide[16] = t

def KF_ELT(wide, r, s, k):
    THETA(P(wide, Pn[r]))
    RHO(P(wide, Pn[r]))
    KHI(P(wide, Pn[s]))
    wide[ 0] = wide[ 0] ^ k

def KECCAK_F_1600(wide):
    for j in range(24):
        KF_ELT(wide, 0,  1, RC[j + 0])
        P1_TO_P0(wide)

class keccak:
    def __init__(self, out_size):
        self.init(out_size)

    def init(self, out_size):
        self.out_size = out_size
        self.wide = list(0 for i in range(25))
        #
        # Initialization for the "lane complement".
        #
        self.wide[ 1] = 0xFFFFFFFFFFFFFFFF
        self.wide[ 2] = 0xFFFFFFFFFFFFFFFF
        self.wide[ 8] = 0xFFFFFFFFFFFFFFFF
        self.wide[12] = 0xFFFFFFFFFFFFFFFF
        self.wide[17] = 0xFFFFFFFFFFFFFFFF
        self.wide[20] = 0xFFFFFFFFFFFFFFFF
        self.ptr = 0
        self.lim = 200 - (out_size >> 2)

        self.buf = bytearray(144)

    def INPUT_BUF(self, buf, size):
        for j in range(0, size, 8):
            self.wide[j >> 3] ^= struct.unpack('<Q', buf[j:j+8])[0]

    def core(self, data, nlen, lim):
        buf = self.buf;
        ptr = self.ptr;

        if nlen < (lim - ptr):
            buf[ptr:ptr + nlen] = data
            self.ptr = ptr + nlen
            return

        while nlen > 0:
            clen = (lim - ptr)
            if clen > nlen:
                clen = nlen
            buf[ptr:ptr + clen] = data
            ptr += clen
            data = data[clen:]
            nlen -= clen
            if ptr == lim:
                self.INPUT_BUF(buf, lim)
                KECCAK_F_1600(self.wide)
                ptr = 0
        self.ptr = ptr

    def write(self, data):
        self.core(data, len(data), 136)

    def digest(self):
        d = self.out_size // 8
        lim = {28: 144, 32: 136, 48: 104, 64: 72}[d]
        utmp = bytearray(lim + 1)

        eb = 1
        if self.ptr == (lim - 1):
            utmp[0] = eb | 0x80
            j = 1
        else:
            j = lim - self.ptr
            utmp[0] = eb
            utmp[j - 1] = 0x80
        self.core(utmp, j, lim)
        # Finalize the "lane complement"
        self.wide[ 1] = SPH_T64(~self.wide[ 1])
        self.wide[ 2] = SPH_T64(~self.wide[ 2])
        self.wide[ 8] = SPH_T64(~self.wide[ 8])
        self.wide[12] = SPH_T64(~self.wide[12])
        self.wide[17] = SPH_T64(~self.wide[17])
        self.wide[20] = SPH_T64(~self.wide[20])
        for j in range(0, d, 8):
            utmp[j:j+8] = struct.pack('<Q', self.wide[j >> 3])
        self.init(d << 3)
        return bytes(utmp[:d])

keccak256 = lambda: keccak(256)
