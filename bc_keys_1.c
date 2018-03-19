#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

int main(){

    printf("\nOpenSSL version: %s\n\n",OPENSSL_VERSION_TEXT);


    // 1. Генерим keypair
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    if(!EC_KEY_generate_key(key)){
        printf("GENERATE KEY FAIL\n"); 
        return 1;
    }
    
    // 2. Выводим на экран приватный ключ
    const BIGNUM *priv_bn;
    uint8_t priv[32];
    int i;
    
    // 2.1 Скопировать приватный ключ в BIGNUM
    priv_bn = EC_KEY_get0_private_key(key);
    
    // 2.2 Перекодировать BIGNUM в массив
    BN_bn2bin(priv_bn, priv);
    
    // 2.3 Распечатать приватный ключ
    printf("Private key is:\n");
    
    for (i = 0; i < 32; i++) {
        printf("%.2x",priv[i]);
    }
    
    printf("\n\n");
    
    // 3. Устанавливаем для публичного ключа форму хранения/представления UNCOMPRESSED
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
    
    // Внутри EC_KEY публичный ключ хранится в объекте EC_POINT. Функция
    // i2o_ECPublicKey позволяет сконвертировать публичный ключ из EC_POINT в массив.
    // Другая функция o2i_ECPublicKey делает обратное действие - берет байтовый массив
    // и загоняет его в EC_KEY в виде объекта EC_POINT.
    u_int8_t pubSize = i2o_ECPublicKey(key, NULL);
    
    if(!pubSize){
        printf("PUB KEY TO DATA ZERO\n"); 
        return 1;
    }

    u_int8_t * pubKey = malloc(pubSize);
    u_int8_t * pubKey2 = pubKey;
    if(i2o_ECPublicKey(key, &pubKey2) != pubSize){
        printf("PUB KEY TO DATA FAIL\n"); 
        return 1;
    }

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
    
    EC_KEY_free(key);
    return 0;
}
