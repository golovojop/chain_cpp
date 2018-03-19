#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>


// Приватный ключ, который я получил с помощью OpenSSL.

/*
    По приватному ключу генерим публичный. Потом оба ключа выводим
    на экран и сравниваем с эталонными.
*/

/*

uint8_t priv_bytes[32] = {
    0xea, 0xe3, 0xdb, 0x12, 0x0c, 0x5c, 0xf5, 0xc7,
    0x0f, 0x32, 0xad, 0x6c, 0xcd, 0xb4, 0x76, 0x94,
    0x45, 0x7c, 0x14, 0x4a, 0x20, 0x91, 0xa1, 0x8a,
    0xbd, 0xa3, 0xbc, 0xb2, 0xf0, 0x04, 0x22, 0x89 };
*/


uint8_t priv_bytes[32] = {
 0x8e, 0x16, 0x6f, 0x8c, 0x1f, 0x63, 0xcc, 0x1d,
 0x6d, 0xaa, 0x54, 0xda, 0x8b, 0x53, 0x7c, 0xf1,
 0x10, 0xb8, 0x33, 0xa6, 0x85, 0xa2, 0x77, 0x7e,
 0x48, 0x73, 0x03, 0x83, 0x0a, 0x22, 0x12, 0x23};


// Это тот же приватный ключ в строковом представлении
char priv_exp[] = "eae3db120c5cf5c70f32ad6ccdb47694457c144a2091a18abda3bcb2f0042289";
char pub_exp[] =  "04012e197e07d84ea930dbbd73b21732c50068dff7806d407d0977838aa3fa6df5e312a51948e08695ad9bedc1344a46658a1837b943abbc8eefea9e571dc9f03a";


int main(){

    printf("\nOpenSSL version,  %s\n\n",OPENSSL_VERSION_TEXT);

    const EC_GROUP *group;
    BIGNUM *bn_priv_1;
    BN_CTX *ctx;
    EC_POINT *pub;
    
    // 1.1 Создаем пустой контейнер ключей EC_KEY
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);

    // 1.2 Поместим в него наш приватный ключ, который сгенерили через OpenSSL.
    // Сначала переводим массив в BIGNUM, затем BIGNUM в EC_KEY
    bn_priv_1 = BN_new();
    BN_bin2bn(priv_bytes, 32, bn_priv_1);
    EC_KEY_set_private_key(key, bn_priv_1);

    // 1.3 Теперь нужно вычислить публичный ключ по приватному. Для вычислений
    // потребуется контекст BN_CTX
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, bn_priv_1, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);

    // 2. Выводим на экран приватный ключ из EC_KEY и сравниваем с ожидаемым
    const BIGNUM *bn_priv_2;
    uint8_t priv[32];
    int i;

    printf("\nExpected private key:\n%s\n", priv_exp);

    // 2.1 Скопировать приватный ключ в BIGNUM
    bn_priv_2 = EC_KEY_get0_private_key(key);
    
    // 2.2 Перекодировать BIGNUM в массив
    BN_bn2bin(bn_priv_2, priv);
    
    // 2.3 Распечатать приватный ключ
    printf("Private key from EC_KEY:\n");
    
    for (i = 0; i < 32; i++) {
        printf("%.2x",priv[i]);
    }

    // ----------------------------------------------------------------------------------------
    //
    //	РАБОТАЕМ С ПУБЛИЧНЫМ КЛЮЧЕМ
    //    
    // 3. Устанавливаем для публичного ключа форму хранения/представления UNCOMPRESSED
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    
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

    printf("\n\nExpected puplic key:\n%s\n", pub_exp);
    printf("Uncompressed public key is:\n");    
    for (i = 0; i < pubSize; i++) {
        printf("%.2x",pubKey[i]);
    }
    
    printf("\n\n");
    free(pubKey);

    // 4. Устанавливаем для публичного ключа форму хранения/представления COMPRESSED
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    
    pubSize = i2o_ECPublicKey(key, NULL);
    
    pubKey = malloc(pubSize);
    pubKey2 = pubKey;
    if(i2o_ECPublicKey(key, &pubKey2) != pubSize){
        printf("PUB KEY TO DATA FAIL\n"); 
        return 1;
    }

    printf("Compressed public key is:\n");    
    for (i = 0; i < pubSize; i++) {
        printf("%.2x",pubKey[i]);
    }
    printf("\n\n");
    free(pubKey);

/*
    u_int8_t * hash = malloc(SHA256_DIGEST_LENGTH);
    
    SHA256(pubKey, pubSize, hash);
    
    for (int x = 0; x < 32; x++) {
        printf("%.2x",hash[x]);
    }
    
    printf("\n\n");
    free(hash);
    
*/
    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv_1);
//    BN_clear_free(bn_priv_2);
    
    EC_KEY_free(key);
    return 0;
}
