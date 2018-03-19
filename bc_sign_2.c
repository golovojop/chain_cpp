#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include "./h/common.h"
#include "./h/ec.h"
#include "./h/hash.h"

// Приватный ключ, который я получил с помощью OpenSSL.

/*
*/

uint8_t priv_bytes[32] = {
    0xea, 0xe3, 0xdb, 0x12, 0x0c, 0x5c, 0xf5, 0xc7,
    0x0f, 0x32, 0xad, 0x6c, 0xcd, 0xb4, 0x76, 0x94,
    0x45, 0x7c, 0x14, 0x4a, 0x20, 0x91, 0xa1, 0x8a,
    0xbd, 0xa3, 0xbc, 0xb2, 0xf0, 0x04, 0x22, 0x89 };
    

const char message[] = "This is a very confidential message\n";
const char digest_exp[] = "4554813e91f3d5be790c7c608f80b2b00f3ea77512d49039e9e3dc45f89e2f01";

int main(){

    printf("\nOpenSSL version,  %s\n\n",OPENSSL_VERSION_TEXT);

    const EC_GROUP *group;
    BIGNUM *bn_priv_1;
    BN_CTX *ctx;
    EC_POINT *pub;
    int i;
    
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

    // 2. Теперь создаем сигнатуру
    uint8_t digest[32];
    ECDSA_SIG *signature;
    uint8_t *der, *der_copy;
    size_t der_len;

    // 2.1 Получаем хэш сообщения
    bc_sha256(digest, (uint8_t*)message, strlen(message));
    
    // 2.1.1 Печатаем хэш
    printf("Expected digest is:\n%s\n", digest_exp);
    printf("Calculated digest is:\n");
    
    for (i = 0; i < 32; i++) {
        printf("%.2x",digest[i]);
    }
    printf("\n\n");
    
    
    // 2.2 Вычисляем сигнатуру и выводим на экран
    signature = ECDSA_do_sign(digest, sizeof(digest), key);
    printf("Calculated signature is:\n");
    
//    char * nnn = BN_bn2hex(signature->r);
    
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));

    // 2.3 Конвертируем сигнатуру в формат DER и выводим на экран
    der_len = ECDSA_size(key);
    der = calloc(der_len, sizeof(uint8_t));
    der_copy = der;
    i2d_ECDSA_SIG(signature, &der_copy);
    
    printf("\nDER encoded:\n");
    
    for (i = 0; i < der_len; i++) {
        printf("%.2x",der[i]);
    }
    printf("\n\n");


    // 3. Выполнить проверку сигнатуры. Так как в реальных условиях мы знаем только само сообщение
    // и публичный ключ подписавшего, то будем работать с новой структурой EC_KEY, которая
    // содержит только публичный ключ. Не забывай, что в качестве подписанного сообщения
    // выступает хэш строки - digest.
    EC_KEY * pubKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_public_key(pubKey, pub);

    int nValid = ECDSA_do_verify(digest, 32, signature, pubKey);
    printf("\nValidation result is: %d\n", nValid);
    
    if (nValid == -1) {
	printf("Error\n");
    }
    else if (nValid == 0) {
	printf("Incorest signature\n");
    }
    else {   /* ret == 1 */
	printf("Verified\n");
    }
    
    
    free(der);
    ECDSA_SIG_free(signature);    
    

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv_1);
    
    EC_KEY_free(key);
    EC_KEY_free(pubKey);

    return 0;
}
