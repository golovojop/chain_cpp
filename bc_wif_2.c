#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "./h/base58.h"
#include "./h/hash.h"


// Приватный ключ, который я получил с помощью OpenSSL.

uint8_t priv_bytes[32] = {
    0xea, 0xe3, 0xdb, 0x12, 0x0c, 0x5c, 0xf5, 0xc7,
    0x0f, 0x32, 0xad, 0x6c, 0xcd, 0xb4, 0x76, 0x94,
    0x45, 0x7c, 0x14, 0x4a, 0x20, 0x91, 0xa1, 0x8a,
    0xbd, 0xa3, 0xbc, 0xb2, 0xf0, 0x04, 0x22, 0x89 };

// Это тот же приватный ключ в строковом представлении
char priv_exp[] = "eae3db120c5cf5c70f32ad6ccdb47694457c144a2091a18abda3bcb2f0042289";

#define	KEY_PRIV_SIZE 	32
#define KEY_WIF_SIZE	34
#define KEY_PUB_COMP	1
#define KEY_PRIV_T3	0xef
#define KEY_PUB_T3	0x6f


// ------------------------------------------------------------------------------------------
void print_bytes(const char * Header, uint8_t * array, int len){

    printf(Header);
    for (int i = 0; i < len; i++) {
	printf("%.2x", array[i]);
    }
    printf("\n");
}

// ------------------------------------------------------------------------------------------

int main(){

    printf("\n\nPrivate key -> WIF (encode\\decode)\n\n");

    const EC_GROUP *group;
    BIGNUM *bn_priv;
    BN_CTX *ctx;
    EC_POINT *pub;
    
    // --------------------------------------------------------------------------------------
    // Создать ключевую пару
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);

    // 1.1 Упаковать приватный ключ
    bn_priv = BN_new();
    BN_bin2bn(priv_bytes, KEY_PRIV_SIZE, bn_priv);
    EC_KEY_set_private_key(key, bn_priv);

    // 1.2 Упаковать публичный ключ
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, bn_priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);
    
    
    // --------------------------------------------------------------------------------------
    // 2.1 Создаем WIF (из приватного ключа)
    
    uint8_t wif_bytes[KEY_WIF_SIZE];
    char * wif;
    
    wif_bytes[0] = KEY_PRIV_T3;					// Testnet3 prefix
    memcpy(wif_bytes + 1, priv_bytes, sizeof(priv_bytes));
    wif_bytes[KEY_WIF_SIZE - 1] = KEY_PUB_COMP;			// For compressed public key
    
    wif = bc_base58check(wif_bytes, sizeof(wif_bytes));
    

    print_bytes("\n\nRaw private key:\n", priv_bytes, KEY_PRIV_SIZE);
    print_bytes("\nRaw WIF bytes:\n", wif_bytes, KEY_WIF_SIZE);
    printf("\nEncoded WIF:\n%s\n", wif);

    // 2.2 Декодируем WIF, чтобы снова получить приватный ключ
    BIGNUM *bn_wif = BN_new();
    int nDecoded =  bc_base58_decode(bn_wif, (const char *)wif, strlen(wif));
    
    if(nDecoded){
    
        memset(wif_bytes, 0, KEY_WIF_SIZE);
        BN_bn2bin((const BIGNUM *)bn_wif, wif_bytes);
	print_bytes("\nDecoded WIF:\n", wif_bytes, KEY_WIF_SIZE);
	print_bytes("\nDecoded private key:\n", wif_bytes + 1, KEY_WIF_SIZE - 2);
    }
    
    BN_clear_free(bn_wif);
    
    // --------------------------------------------------------------------------------------
    
    free(wif);
    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv);
    
    EC_KEY_free(key);
    return 0;
}
