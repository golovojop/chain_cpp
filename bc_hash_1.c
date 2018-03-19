#include "./h/common.h"
#include "./h/hash.h"

int main() {
    char message[] = "Hello Bitcoin!";
    uint16_t prefix = 0xd17f;
    uint8_t suffix = 0x8c;
    uint8_t digest[32];
    uint8_t ser[35];

    const char sha256_exp[] = "518ad5a375fa52f84b2b3df7933ad685eb62cf69869a96731561f94d10826b5c";
    const char hash256_exp[] = "90986ea4e28b847cc7f9beba87ea81b221ca6eaf9828a8b04c290c21d891bcda";
    const char ser_exp[] = "7fd190986ea4e28b847cc7f9beba87ea81b221ca6eaf9828a8b04c290c21d891bcda8c";

    /* */

    /* SHA-2 digest is big-endian */

    bc_sha256(digest, (uint8_t *)message, strlen(message));
    bc_print_hex("SHA256(message)      ", digest, 32);
    printf("SHA256(message) (exp): %s\n", sha256_exp);
    
// --------------------------------------------------------------
    uint8_t byte_array[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    bc_print_hex("test message      ", byte_array, 5);
// --------------------------------------------------------------
    

    bc_sha256(digest, digest, 32);
    bc_print_hex("hash256(message)      ", digest, 32);
    printf("hash256(message) (exp): %s\n", hash256_exp);

    *(uint16_t *)(ser) = bc_eint16(BC_LITTLE, prefix);
    memcpy(ser + 2, digest, 32);
    *(ser + 2 + 32) = suffix;

    bc_print_hex("ser      ", ser, sizeof(ser));
    printf("ser (exp): %s\n", ser_exp);

    return 0;
}

