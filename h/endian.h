#ifndef __ENDIAN_H
#define __ENDIAN_H

#include <stdint.h>
#include <string.h>
#include "common.h"

typedef enum {
    BC_BIG,
    BC_LITTLE
} bc_endian_t;

// Определить режим ENDIAN на текущем компе
bc_endian_t bc_host_endian() {
    static const union {
        uint16_t i;
        uint8_t c[2];
    } test = { 0x1234 };

    return ((test.c[0] == 0x34) ? BC_LITTLE : BC_BIG );
}

// Инвертировать порядок байтов в uint16
uint16_t bc_swap16(uint16_t n) {
    return (n >> 8) |
           ((n & 0xff) << 8);
}

// Инвертировать порядок байтов в uint32
uint32_t bc_swap32(uint32_t n) {
    return (n >> 24) |
           ((n & 0xff0000) >> 8) |
           ((n & 0xff00) << 8) |
           ((n & 0xff) << 24);
}

// Инвертировать порядок байтов в uint64
uint64_t bc_swap64(uint64_t n) {
    return (n >> 56) |
           ((n & 0xff000000000000) >> 40) |
           ((n & 0xff0000000000) >> 24) |
           ((n & 0xff00000000) >> 8) |
           ((n & 0xff000000) << 8) |
           ((n & 0xff0000) << 24) |
           ((n & 0xff00) << 40) |
           ((n & 0xff) << 56);
}

// Сконвертировать аргумент в нужный ENDIAN
uint16_t bc_eint16(bc_endian_t e, uint16_t n) {
    if (bc_host_endian() == e) {
        return n;
    }
    return bc_swap16(n);
}

// Сконвертировать аргумент в нужный ENDIAN
uint32_t bc_eint32(bc_endian_t e, uint32_t n) {
    if (bc_host_endian() == e) {
        return n;
    }
    return bc_swap32(n);
}

// Сконвертировать аргумент в нужный ENDIAN
uint64_t bc_eint64(bc_endian_t e, uint64_t n) {
    if (bc_host_endian() == e) {
        return n;
    }
    return bc_swap64(n);
}

// Инвертировать порядок байтов в аргументе произвольной длины
void bc_reverse(uint8_t *dst, size_t len) {
    size_t i;
    const size_t stop = len >> 1;
    for (i = 0; i < stop; ++i) {
        uint8_t *left = dst + i;
        uint8_t *right = dst + len - i - 1;
        const uint8_t tmp = *left;
        *left = *right;
        *right = tmp;
    }
}

#endif