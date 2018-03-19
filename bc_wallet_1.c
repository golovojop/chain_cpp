#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "./h/base58.h"
#include "./h/hash.h"


// Приватный ключ, который я получил с помощью OpenSSL.

//uint8_t priv_bytes[32] = {
//    0xea, 0xe3, 0xdb, 0x12, 0x0c, 0x5c, 0xf5, 0xc7,
//    0x0f, 0x32, 0xad, 0x6c, 0xcd, 0xb4, 0x76, 0x94,
//    0x45, 0x7c, 0x14, 0x4a, 0x20, 0x91, 0xa1, 0x8a,
//    0xbd, 0xa3, 0xbc, 0xb2, 0xf0, 0x04, 0x22, 0x89 };
    

uint8_t priv_bytes[32] = {
    0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
    0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
    0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
    0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };
    

// Это тот же приватный ключ в строковом представлении
char priv_exp[] = "eae3db120c5cf5c70f32ad6ccdb47694457c144a2091a18abda3bcb2f0042289";


#define	KEY_PRIV_SIZE 	32
#define KEY_WIF_SIZE	34
#define KEY_PUB_COMP	1
#define KEY_PRIV_T3	0xef
#define KEY_PRIV_MN	0x80
#define KEY_PUB_T3	0x6f
#define KEY_PUB_MN	0x00
#define SHA256_SIZE	32
#define HASH160_SIZE	20

//#define MAINNET

#ifdef MAINNET
    #define KEY_PRIV_PREFIX KEY_PRIV_MN
    #define KEY_PUB_PREFIX KEY_PUB_MN
#else
    #define KEY_PRIV_PREFIX KEY_PRIV_T3
    #define KEY_PUB_PREFIX KEY_PUB_T3
#endif



int main(){

    printf("Create WIF for Testnet3 from a private key\n\n");

    const EC_GROUP *group;
    BIGNUM *bn_priv;
    BN_CTX *ctx;
    EC_POINT *pub;
    
    // --------------------------------------------------------------------------------------
    // 1.1 Создаем пустой контейнер ключей EC_KEY
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);

    // 1.2 Поместим в него наш приватный ключ, который сгенерили через OpenSSL.
    // Сначала переводим массив в BIGNUM, затем BIGNUM в EC_KEY
    bn_priv = BN_new();
    BN_bin2bn(priv_bytes, KEY_PRIV_SIZE, bn_priv);
    EC_KEY_set_private_key(key, bn_priv);

    // 1.3 Теперь нужно вычислить публичный ключ по приватному. Для вычислений
    // потребуется контекст BN_CTX
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, bn_priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);
    
    
    // --------------------------------------------------------------------------------------
    /* 2. Работа с приватным ключом
	Упаковать приватный ключ в WIF (Base58Check)
	Testnet3 prefix (1 byte 0xef) + PrivKey (32 bytes) + CompressedFlag (1 byte - 0x01 optional) 
    */
    
    uint8_t wif_bytes[KEY_WIF_SIZE];
    char * wif;
    
    wif_bytes[0] = KEY_PRIV_PREFIX;					// Testnet3 prefix
    memcpy(wif_bytes + 1, priv_bytes, sizeof(priv_bytes));
    wif_bytes[KEY_WIF_SIZE - 1] = KEY_PUB_COMP;				// For compressed public key
    
    wif = bc_base58check(wif_bytes, sizeof(wif_bytes));
    printf("WIF            : %s\n", wif);
    
    
    // --------------------------------------------------------------------------------------
    /*	3. Работа с публичным ключом

    
    */
// ----------------------------------------------------------------------------------------
    //
    //	РАБОТАЕМ С ПУБЛИЧНЫМ КЛЮЧЕМ
    //    
    // 3. Устанавливаем для публичного ключа форму хранения/представления COMPRESSED
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    
    // Внутри EC_KEY публичный ключ хранится в объекте EC_POINT. Функция
    // i2o_ECPublicKey позволяет сконвертировать публичный ключ из EC_POINT в массив.
    // Другая функция o2i_ECPublicKey делает обратное действие - берет байтовый массив
    // и загоняет его в EC_KEY в виде объекта EC_POINT.
    u_int8_t pubSize = i2o_ECPublicKey(key, NULL);

    u_int8_t * pubKey = malloc(pubSize);
    u_int8_t * pubKey2 = pubKey;
    if(i2o_ECPublicKey(key, &pubKey2) != pubSize){
        printf("PUB KEY TO DATA FAIL\n"); 
        return 1;
    }

    printf("\nCompressed public key is:\n");    
    for (int i = 0; i < pubSize; i++) {
        printf("%.2x",pubKey[i]);
    }
    printf("\n\n");
    
    // 3.1 Формируем ключ для кошелька из публичного ключа
    u_int8_t digest160[1 + HASH160_SIZE];
    
    // a. Вычислить хэш публичного ключа
    bc_hash160(&digest160[1], pubKey, pubSize);
    // b. Добавить признак сети Testnet2
    digest160[0] = KEY_PUB_PREFIX;
    // c. Закодировать ключ в Base58Check
    char * walletKey  = bc_base58check(digest160, sizeof(digest160));
    printf("Wallet key       : %s\n", walletKey);


    free(pubKey);
    free(wif);
    free(walletKey);
    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv);
    
    EC_KEY_free(key);
    return 0;
}
