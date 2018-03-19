#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "./h/base58.h"
#include "./h/hash.h"


#define	KEY_PRIV_SIZE 	32
#define KEY_WIF_SIZE	34
#define KEY_PUB_COMP	1
#define KEY_PRIV_TN	0xef
#define KEY_PRIV_MN	0x80
#define KEY_PUB_TN	0x6f
#define KEY_PUB_MN	0x00
#define SHA256_SIZE	32
#define HASH160_SIZE	20
#define BUF_SIZE 	256


//#define MAINNET

#ifdef MAINNET
    #define KEY_PRIV_PREFIX KEY_PRIV_MN
    #define KEY_PUB_PREFIX KEY_PUB_MN
#else
    #define KEY_PRIV_PREFIX KEY_PRIV_TN
    #define KEY_PUB_PREFIX KEY_PUB_TN
#endif


int main(){


    const EC_GROUP *group;
    BIGNUM *bn_priv_1;
    BN_CTX *ctx;
    EC_POINT *pub;

    printf("\n\n*** Private To Public maker ***\n\n");

    
    // --------------------------------------------------------------------------------------
    // 1.1 Ввести с клавиатуры приватный ключ
    char priv_sz[BUF_SIZE] = {0};
    
    if(INPUT_BAD != bc_getLine("Enter Private key:   ", priv_sz, BUF_SIZE)){
	if(strlen(priv_sz) != (KEY_PRIV_SIZE * 2)){
	    printf("Bad input\n");
	    return 1;
	}
    }
    else {
	printf("Bad input\n");
	return 1;
    }
    
    printf("\nYour Private key is: %s\n", priv_sz);


    // --------------------------------------------------------------------------------------
    // 1.1.1 Сконвертировать строку приватного ключа в байты
    uint8_t priv_bytes[KEY_PRIV_SIZE];
    bc_parse_hex(priv_bytes, priv_sz);
    
    //bc_print_bytes("Priv from atring:", priv_bytes, KEY_PRIV_SIZE);


    // --------------------------------------------------------------------------------------
    // 2.1 Вычислить публичный ключ по приватному
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);

    bn_priv_1 = BN_new();
    BN_bin2bn((uint8_t*)priv_bytes, KEY_PRIV_SIZE, bn_priv_1);
    EC_KEY_set_private_key(key, bn_priv_1);

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, bn_priv_1, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);

    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    u_int8_t pubSize = i2o_ECPublicKey(key, NULL);


    // --------------------------------------------------------------------------------------
    // 3.1 Показать uncompressed public key
    u_int8_t * pubKey = malloc(pubSize);
    u_int8_t * pubKey2 = pubKey;
    if(i2o_ECPublicKey(key, &pubKey2) != pubSize){
        printf("PUB KEY TO DATA FAIL\n"); 
        return 1;
    }

    bc_print_bytes("\nUncompressed public key is:\n", pubKey, pubSize);
    free(pubKey);

    // --------------------------------------------------------------------------------------
    // 4.1 Показать compressed public key
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    
    pubSize = i2o_ECPublicKey(key, NULL);
    
    pubKey = malloc(pubSize);
    pubKey2 = pubKey;
    if(i2o_ECPublicKey(key, &pubKey2) != pubSize){
        printf("PUB KEY TO DATA FAIL\n"); 
        return 1;
    }

    bc_print_bytes("\nCompressed public key is:\n", pubKey, pubSize);

    // --------------------------------------------------------------------------------------
    // 5.1 Создаем WIF из приватного ключа
    uint8_t wif_bytes[KEY_WIF_SIZE] = {0};
    char * wif;
    
    wif_bytes[0] = KEY_PRIV_TN;					// Testnet3 prefix
    memcpy(wif_bytes + 1, priv_bytes, sizeof(priv_bytes));
    wif_bytes[KEY_WIF_SIZE - 1] = KEY_PUB_COMP;			// For compressed public key
    
    wif = bc_base58check(wif_bytes, sizeof(wif_bytes));
    

//    bc_print_bytes("\nRaw WIF bytes:\n", wif_bytes, KEY_WIF_SIZE);
    printf("\nWIF:\n%s\n", wif);
    free(wif);
    
    // --------------------------------------------------------------------------------------
    // 6.1 Формируем адрес для кошелька из публичного ключа
    u_int8_t digest160[1 + HASH160_SIZE];
            
    // a. Вычислить хэш публичного ключа
    bc_hash160(&digest160[1], pubKey, pubSize);
    // b. Добавить признак сети Mainnet или Testnet2
    digest160[0] = KEY_PUB_PREFIX;
    // c. Закодировать ключ в Base58Check
    char * walletKey  = bc_base58check(digest160, sizeof(digest160));
    printf("\nWallet address:\n%s\n\n\n", walletKey);

    free(pubKey);
    free(walletKey);

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv_1);
    
    EC_KEY_free(key);
    return 0;
}