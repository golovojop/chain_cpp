#ifndef __VARINT_H
#define __VARINT_H

#include <stdint.h>
#include "endian.h"


typedef enum {
    BC_VARINT16 = 0xfd,
    BC_VARINT32 = 0xfe,
    BC_VARINT64 = 0xff
} BC_varint_t;


// Прочитать из байтового массива значение varint
uint64_t bc_varint_get(uint8_t *bytes, size_t *len) {

    uint8_t prefix = *bytes;
    uint64_t value;

    // Изначально предполагаем, что длинна переменной - 1 байт
    *len = sizeof(uint8_t);

    if (prefix < BC_VARINT16) {
        value = prefix;
    } else {
	// "Перешагиваем" префикс и встаем на первый байт данных
        uint8_t *ptr = bytes + *len;

        switch (prefix) {
            case BC_VARINT16:
                value = bc_eint16(BC_LITTLE, *(uint16_t *)ptr);
                *len += sizeof(uint16_t);
                break;
            case BC_VARINT32:
                value = bc_eint32(BC_LITTLE, *(uint32_t *)ptr);
                *len += sizeof(uint32_t);
                break;
            case BC_VARINT64:
                value = bc_eint64(BC_LITTLE, *(uint64_t *)ptr);
                *len += sizeof(uint64_t);
                break;
        }
    }

    return value;
}

// Создать из n varint и записать в массив bytes

void bc_varint_set(uint8_t *bytes, uint64_t n, size_t *len) {
    *len = sizeof(uint8_t);

    if (n < BC_VARINT16) {
        *bytes = (uint8_t)n;
    } else {
        uint8_t header;

        if (n <= UINT16_MAX) {
            header = BC_VARINT16;
            *(uint16_t *)(bytes + 1) = bc_eint16(BC_LITTLE, n);
            *len += sizeof(uint16_t);
        } else if (n <= UINT32_MAX) {
            header = BC_VARINT32;
            *(uint32_t *)(bytes + 1) = bc_eint32(BC_LITTLE, n);
            *len += sizeof(uint32_t);
        } else {
            header = BC_VARINT64;
            *(uint64_t *)(bytes + 1) = bc_eint64(BC_LITTLE, n);
            *len += sizeof(uint64_t);
        }

        *bytes = header;
    }
}

size_t bc_varint_size(uint64_t n) {
    
    if (n < BC_VARINT16) {
        return 1;
    } else if (n <= UINT16_MAX) {
        return 1 + sizeof(uint16_t);
    } else if (n <= UINT32_MAX) {
        return 1 + sizeof(uint32_t);
    } else {
        return 1 + sizeof(uint64_t);
    }
}

#endif

