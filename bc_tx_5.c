#include "./h/common.h"
#include "./h/endian.h"
#include "./h/tx.h"
#include "./h/hash.h"
#include "./h/ec.h"

int main() {


    enum {
	SIGHASH_ALL = 1,
        SIGHASH_NONE = 2,
        SIGHASH_SINGLE = 3,
        SIGHASH_ANYONECANPAY = 0x80,
    };

    // Короче, ноеобходимо инициализировать нулями вообще все, иначе там остается мусор, который затем не позволяет нормально работать 
    // с переменными UINT64_T

    bc_txout_t outs 		= {0};
    bc_txout_t prev_outs 	= {0};
    bc_txin_t ins_sign		= {0};
    bc_txin_t ins		= {0};
    bc_outpoint_t outpoint	= {0};
    bc_tx_t tx			= {0};

    uint8_t *msg;
    size_t msg_len;

    /*
	Получатель:
	Wallet address: mpQAaGmXuE913KXujDwX51uoycpw1fzcPV
    */
    const char addr_to[]	= "617078891a7529b047c4478a4fef6cffa06ca3dd";	// Это hash160(raw_public_key)

    /*
	Отправитель:
	Wallet address: mooQHhWnjv3PNtSyqT5QtfL7u3uEVwwaXE
	WIF:		cSLuEiJhszzzJtF5XC63JgtzgjpNnENy2WaTvkvoouD26bx1XzrG
	PrivKey:	8e166f8c1f63cc1d6daa54da8b537cf110b833a685a2777e487303830a221223
    */
    const char addr_me[] 	= "5add5c3a100e4ff2aa740fd76cb92a703479c92e";	// Это hash160(raw_public_key)
    const char pub_my[]		= "020e5658abfcffddf43026355b4ea5cab258f84da49692cff115332d4adb3e40be";
    const char priv_bytes[]	= "8e166f8c1f63cc1d6daa54da8b537cf110b833a685a2777e487303830a221223";

    /*
	ID транзакции источника
    */
    const char txid_src[]	= "86d22dbee3723ff7a35496ee972a40015838d7899c27e40eb1661f4b906ff7bb";


    /* --------------------------------------------------------------------------------------------------------------------*/
    /* Сначала создадим signable body. Это модифицированная транзакция, тело которой будет материалом для цифровой подписи */
    /* --------------------------------------------------------------------------------------------------------------------*/

    /* output 0 (1.3 BTC) */
    bc_txout_create_p2pkh(&outs, 130000000, addr_to);
    /* output of source tx */    
    bc_txout_create_p2pkh(&prev_outs, 131414595, addr_me);
    /* input from utxo (1.31414595 BTC) */
    bc_outpoint_fill(&outpoint, txid_src, 1);
    /* Это модифицированный input, ссылающийся на источник средств */
    bc_txin_create_signable(&ins_sign, &outpoint, &prev_outs);

    /* message */
    tx.version = bc_eint32(BC_LITTLE, 1);
    tx.inputs_count = 1;
    tx.inputs = &ins_sign;
    tx.outputs_count = 1;
    tx.outputs = &outs;
    tx.locktime = 0;
/*
    
        printf("tx.version: %d\n", tx.version);
        printf("inputs count: %d\n", tx.inputs_count);
        bc_print_bytes("tx.inputs[0].outpoint.txid: ", tx.inputs[0].outpoint.txid, 32);
        printf("tx.inputs[0].outpoint.index: %d\n", tx.inputs[0].outpoint.index);
        printf("tx.inputs[0].script_len: %d\n", tx.inputs[0].script_len);
        bc_print_bytes("tx.inputs[0].script: ", tx.inputs[0].script, tx.inputs[0].script_len);
        printf("tx.outputs[0].value: %d\n", tx.outputs[0].value);
        printf("tx.outputs[0].script_len: %d\n", tx.outputs[0].script_len);
        bc_print_bytes("tx.outputs[0].script: ", tx.outputs[0].script, tx.outputs[0].script_len);
*/
    msg_len = bc_tx_size(&tx, BC_SIGHASH_ALL);
    msg = malloc(msg_len);
    bc_tx_serialize(&tx, msg, BC_SIGHASH_ALL);

    /* --------------------------------------------------------------------------------------------------------------------*/
    /* Теперь нужно создать цифровую подпись нашего msg                                                                    */
    /* --------------------------------------------------------------------------------------------------------------------*/

    const EC_GROUP *group;
    BIGNUM *bn_priv;
    BN_CTX *ctx;
    EC_POINT *pub;
    int i;
    
    // 1.1 Создаем пустой контейнер ключей EC_KEY
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);

    // 1.2 Поместим в него наш приватный ключ, который сгенерили через OpenSSL.
    // Сначала переводим массив в BIGNUM, затем BIGNUM в EC_KEY
    bn_priv = BN_new();
    printf("priv key before: %s\n", priv_bytes);
    printf("BN length in hex digits is %d\n", BN_hex2bn(&bn_priv, priv_bytes));
    printf("priv key after:  %s\n", BN_bn2hex((const BIGNUM *)bn_priv));
    
    EC_KEY_set_private_key(key, bn_priv);

    // 1.3 Теперь нужно вычислить публичный ключ по приватному. Для вычислений
    // потребуется контекст BN_CTX
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, bn_priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);

    // 2. Теперь создаем сигнатуру
    uint8_t digest[32];
    ECDSA_SIG *signature;
    uint8_t *der, *der_copy;
    size_t der_len;
                    
    // 2.1 Получаем хэш сообщения
    printf("msg len: %d\n", msg_len);
    bc_print_bytes("msg: ", msg, msg_len);
//    bc_sha256(digest, msg, msg_len);

    bc_hash256(digest, msg, msg_len);

                                
    // 2.1.1 Печатаем хэш
    bc_print_bytes("\nCalculated digest is:\n", digest, 32);

    // 2.2 Вычисляем сигнатуру и выводим на экран
    signature = ECDSA_do_sign(digest, sizeof(digest), key);
    printf("\nCalculated signature is:\n");
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));
    
    
    // 2.3 Конвертируем сигнатуру в формат DER.

    der_len = i2d_ECDSA_SIG(signature, 0);
//    der_len += 1;
    der = calloc(der_len, sizeof(uint8_t));
    memset(der, 0, sizeof(uint8_t));
    der_copy = der;
    i2d_ECDSA_SIG(signature, &der_copy);
    
    // Дописываем в конец флаг SIGHASH_ALL
//    der[der[1]+2] =  SIGHASH_ALL;
    
    bc_print_bytes("new DER: ", der, der_len);
    

    //der_len = ECDSA_size(key);
    //++der_len;					// Дополнительный байт для флага SIGHASH_ALL 
    //der = calloc(der_len, sizeof(uint8_t));
    //der_copy = der;
    //i2d_ECDSA_SIG(signature, &der_copy);
    
    // Корректировка длины. См здесь https://bitcoin.stackexchange.com/questions/37125/how-are-sighash-flags-encoded-into-a-signature
//    der_len = der[1] + 1;
//    der[der_len - 1] = SIGHASH_ALL;
    bc_print_bytes("\nDER encoded:\n", der, der_len);
    
    // Сигнатуру в строку
    char * der_sz = bc_bytes2hex(der, der_len);
    if(der_sz) {
	printf("DER to string verification:\n%s\n", der_sz);
    }
    
                    

    // 3. Выполнить проверку сигнатуры. Так как в реальных условиях мы знаем только само сообщение
    // и публичный ключ подписавшего, то будем работать с новой структурой EC_KEY, которая
    // содержит только публичный ключ. Не забывай, что в качестве подписанного сообщения
    // выступает хэш строки - digest.
    EC_KEY * pubKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_public_key(pubKey, pub);
                    
    int nValid = ECDSA_do_verify(digest, 32, signature, pubKey);
    printf("\nSignature validation result: %d\n", nValid);
                                
    if (nValid == -1) {
	printf("Error\n\n");
    }
    else if (nValid == 0) {
	printf("Incorest signature\n\n");
    }
    else {   /* ret == 1 */
	printf("Verified\n\n");
    }

    /* --------------------------------------------------------------------------------------------------------------------*/
    /* Ну а теперь самое главное - нужно сгенерить транзакцию.                                                             */
    /* --------------------------------------------------------------------------------------------------------------------*/

    uint8_t *rawtx;
    size_t rawtx_len;

    bc_txin_create_p2pkh(&ins, &outpoint, der_sz, pub_my, BC_SIGHASH_ALL);

    tx.version = bc_eint32(BC_LITTLE, 1);
    tx.outputs_count = 1;
    tx.outputs = &outs;
    tx.inputs_count = 1;
    tx.inputs = &ins;
    tx.locktime = 0;

    rawtx_len = bc_tx_size(&tx, BC_SIGHASH_ALL);
    rawtx = malloc(rawtx_len);
    bc_tx_serialize(&tx, rawtx, BC_SIGHASH_ALL);

    printf("RawTx len: %d\n", rawtx_len);
    bc_print_bytes("RawTx:\n", rawtx, rawtx_len);


    free(rawtx);
    free(der);
    ECDSA_SIG_free(signature);    

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv);
                            
    EC_KEY_free(key);
    EC_KEY_free(pubKey);


    // -----------------------------------------------------------
    free(msg);
    bc_txout_destroy(&outs);
    bc_txout_destroy(&prev_outs);
    bc_txin_destroy(&ins_sign);

    return 0;
}
