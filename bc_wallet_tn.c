#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "./h/base58.h"
#include "./h/hash.h"


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

    printf("\nKey pair for Testnet3\n\n");
    
    // --------------------------------------------------------------------------------------
    //	1.1 Создаем контейнер ключей, указывая группу
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);
    //	1.2 Генерим ключи в контейнере
    if(0 == EC_KEY_generate_key(key)) {
	printf("Error EC_KEY_generate_key\n");
	return 0;
    }
    
    // ---------------------------oOC-----------------------------------------------------------
    /* 2. Работа с приватным ключом
	Упаковать приватный ключ в WIF (Base58Check)
	Testnet3 prefix (1 byte 0xef) + PrivKey (32 bytes) + CompressedFlag (1 byte - 0x01 optional) 
    */

    uint8_t priv_bytes[KEY_PRIV_SIZE] = {0};
    uint8_t wif_bytes[KEY_WIF_SIZE];
    char * wif;

    // 2.1 Прочитать приватный ключ и сохранить в массив в форме big-endian
    const BIGNUM *bn_priv = EC_KEY_get0_private_key(key);
    BN_bn2bin(bn_priv, priv_bytes);

/*
    printf("\nRaw private key:\n");    
    for (int i = 0; i < 32; i++) {
        printf("%.2x",priv_bytes[i]);
    }
    printf("\n\n");
*/

    // 2.2 Сгенерить WIF
    wif_bytes[0] = KEY_PRIV_PREFIX;					// Mainnet or Testnet3 prefix
    memcpy(wif_bytes + 1, priv_bytes, sizeof(priv_bytes));
    wif_bytes[KEY_WIF_SIZE - 1] = KEY_PUB_COMP;				// For compressed public key

    wif = bc_base58check(wif_bytes, sizeof(wif_bytes));
    printf("WIF:\n%s\n", wif);

    BN_clear_free((BIGNUM *)bn_priv);
    free(wif);
    
    
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
        printf("Pubkey to data fail\n"); 
        return 0;
    }

/*
    printf("\nCompressed public key is:\n");    
    for (int i = 0; i < pubSize; i++) {
        printf("%.2x",pubKey[i]);
    }
    printf("\n\n");
*/
    
    // 3.1 Формируем адрес для кошелька из публичного ключа
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
//    EC_KEY_free(key);
    return 0;
}