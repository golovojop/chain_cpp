
#ifndef __EC_H
#define __EC_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>


EC_KEY *bc_ec_new_keypair(const uint8_t *priv_bytes) {
    EC_KEY *key;
    BIGNUM *priv;
    BN_CTX *ctx;
    const EC_GROUP *group;
    EC_POINT *pub;

    /* Инициализируем пустую стркутуру для хранения пары ключей. Нужно указать группу эллипт кривой*/

    key = EC_KEY_new_by_curve_name(NID_secp256k1);

    /* 1. Создаем новый BIGNUM */
    /* 2. Копируем в него (bin to BIGNUM) наш массив байтов, представляющий приватный ключ */
    /* 3. Затем BIGNUM помещаем в структуру EC_KEY в качестве приватного ключа */

    priv = BN_new();
    BN_bin2bn(priv_bytes, 32, priv);
    EC_KEY_set_private_key(key, priv);

    /* Инициализируем новый контекст */
    
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    
    
    // Объект EC_GROUP представляет группу, которую мы задали при создании key. Объект
    // группы включает в себя все необходимые характеристики для дальнейшей генерации
    // ключей. См здесь: https://en.bitcoin.it/wiki/Secp256k1. Там и порядок поля,
    // базовая точка (генератор), order подгруппы, cofactor.

    group = EC_KEY_get0_group(key);			// Получаем группу (secp256k1)
    pub = EC_POINT_new(group);				// Узнаем её генератор G (base point)
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);	// Вычисляем pubkey и сохраняем в pub
    EC_KEY_set_public_key(key, pub);			// Устанавливаем pubkey в структуру EC_KEY

    /* release resources */

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(priv);

    return key;
}

EC_KEY *bc_ec_new_pubkey(const uint8_t *pub_bytes, size_t pub_len) {
    EC_KEY *key;
    const uint8_t *pub_bytes_copy;

    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    pub_bytes_copy = pub_bytes;
    o2i_ECPublicKey(&key, &pub_bytes_copy, pub_len);

    return key;
}

#endif

