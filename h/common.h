#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "endian.h"

#define INPUT_OK	0
#define INPUT_BAD	1


// Байтовый массив в hex-строку

char * bc_bytes2hex (uint8_t * bin, size_t len) {

    char hex_str[]= "0123456789abcdef";
    char *ptr = malloc(len * 2 + 1);
    
    ptr[len * 2] = 0;
                                                    
    for (size_t i = 0; i < len; i++){
	ptr[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
	ptr[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }
    
    return ptr;
}

// Печатает байтовый массив в шестнадцатеричном виде. Младший байт массива
// печатается слева, старший - справа.

void bc_print_hex(const char *label, const uint8_t *v, size_t len) {
    size_t i;

    printf("%s: ", label);
    
    for (i = 0; i < len; ++i) {
        printf("%02x", v[i]);
    }
    printf("\n");
}

// ------------------------------------------------------------------------------------------
// Мой аналог
void bc_print_bytes(const char * Header, uint8_t * array, int len){

    printf(Header);
    for (int i = 0; i < len; i++) {
	printf("%.2x", array[i]);
    }
    printf("\n");
}
    	        


// Конвертировать строковое представление отдельной шестнадцатеричной цифры в реальное число.
// Например символ 'a' превратится в число 10, а символ 'c' в 12

uint8_t bc_hex2byte(const char ch) {
    if ((ch >= '0') && (ch <= '9')) {
        return ch - '0';
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        return ch - 'a' + 10;
    }
    return 0;
}

// Конвертирует строковое представление длинного шестнадцатеричного числа в байтовый массив.
// При этом младший байт строки становится младшим байтом массива. Например, строка 'a8bd5f'
// превратится в массив {0xa8, 0xbd, 0x5f}.
// Поэтому нужно самостоятельно контролировать Endiannes.
// Количество шестнадцатеричных цифр всегда четное, потому что один байт состоит
// из двух таких цифр.

void bc_parse_hex(uint8_t *v, const char *str) {
    const size_t count = strlen(str) / 2;
    size_t i;

    for (i = 0; i < count; ++i) {
        const char hi = bc_hex2byte(str[i * 2]);
        const char lo = bc_hex2byte(str[i * 2 + 1]);

        v[i] = hi * 16 + lo;
    }
}

// Тоже самое, что и предыдущая ф-ция, только место для результирующего массива выделяется здесь.
// Аргумент len - лишний.

uint8_t *bc_alloc_hex(const char *str, size_t *len) {
    const size_t count = strlen(str) / 2;
    size_t i;

    uint8_t *v = malloc(count);
    memset(v, 0, count);

    for (i = 0; i < count; ++i) {
        const char hi = bc_hex2byte(str[i * 2]);
        const char lo = bc_hex2byte(str[i * 2 + 1]);

        v[i] = hi * 16 + lo;
    }

    *len = count;

    return v;
}

// ------------------------------------------------------------------------------------------

int bc_getLine(char *prmpt, char *buff, size_t len) {

    memset(buff, 0, len);
    
    printf ("%s", prmpt);
    fflush (stdout);
    
    if(fgets (buff, len, stdin) == NULL) {
	printf("err: No input\n");
	return INPUT_BAD;
    }
    
    // Важно, нужно убрать символ конца строки, иначе перекодировка не будет работать
    if(buff[strlen(buff) - 1] == '\n'){
      buff[strlen(buff) - 1] = 0;
    }
    
    return INPUT_OK;

}



#endif

