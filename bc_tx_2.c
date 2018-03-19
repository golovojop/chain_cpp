#include "./h/common.h"
#include "./h/endian.h"
#include "./h/tx.h"
#include "./h/hash.h"
#include "./h/ec.h"

int main() {

    // Короче, ноеобходимо инициализировать нулями вообще все, иначе там остается мусор, который затем не позволяет нормально работать 
    // переменными UINT64_T

    bc_txout_t outs[2] 		= {0};
    bc_txout_t prev_outs[1] 	= {0};
    bc_txin_t ins_sign[1]	= {0};
    bc_outpoint_t outpoint	= {0};
    bc_tx_t tx			= {0};

    uint8_t *msg;
    size_t msg_len;

    const char msg_exp[] = "0100000001f3a27f485f9833c8318c490403307fef1397121b5dd8fe70777236e7371c4ef3000000001976a9146bf19e55f94d986b4640c154d86469934191951188acffffffff02e0fe7e01000000001976a91418ba14b3682295cb05230e31fecb00089240660888ace084b003000000001976a9146bf19e55f94d986b4640c154d86469934191951188ac0000000001000000";

    /*
	Wallet address: mpQAaGmXuE913KXujDwX51uoycpw1fzcPV
    */

    const char addr_rcv[]	= "617078891a7529b047c4478a4fef6cffa06ca3dd";	// Это hash160(raw_public_key)

    /*
	Wallet address: mooQHhWnjv3PNtSyqT5QtfL7u3uEVwwaXE
	WIF:		cSLuEiJhszzzJtF5XC63JgtzgjpNnENy2WaTvkvoouD26bx1XzrG
	PrivKey:	8e166f8c1f63cc1d6daa54da8b537cf110b833a685a2777e487303830a221223
    */
    const char addr_my[] 	= "5add5c3a100e4ff2aa740fd76cb92a703479c92e";	// Это hash160(raw_public_key)
    const char priv_bytes[]	= "8e166f8c1f63cc1d6daa54da8b537cf110b833a685a2777e487303830a221223";


    /* --------------------------------------------------------------------------------------------------------------------*/
    /* Сначала создадим signable body. Это модифицированная транзакция, тело которой будет материалом для цифровой подписи */
    /* --------------------------------------------------------------------------------------------------------------------*/

    /* output 0 (1.1 BTC) */
    bc_txout_create_p2pkh(&outs[0], 110000000, addr_rcv);
    /* output 1 (change 0.21301595 BTC) */
    bc_txout_create_p2pkh(&outs[1], 21301595, addr_my);
    /* output of source tx */    
    bc_txout_create_p2pkh(&prev_outs[0], 131414595, addr_my);
    /* input from utxo (1.31414595 BTC) */
    bc_outpoint_fill(&outpoint, "86d22dbee3723ff7a35496ee972a40015838d7899c27e40eb1661f4b906ff7bb", 1);
    /* Это модифицированный input, ссылающийся на источник средств */
    bc_txin_create_signable(&ins_sign[0], &outpoint, &prev_outs[0]);

    /* message */
    tx.version = bc_eint32(BC_LITTLE, 1);
    tx.outputs_count = 2;
    tx.outputs = outs;
    tx.inputs_count = 1;
    tx.inputs = ins_sign;
    tx.locktime = 0;

    msg_len = bc_tx_size(&tx, BC_SIGHASH_ALL);
    msg = malloc(msg_len);
    bc_tx_serialize(&tx, msg, BC_SIGHASH_ALL);

    printf("msg len: %d\n", msg_len);
    bc_print_hex("msg      ", msg, msg_len);
    printf("msg (exp): %s\n", msg_exp);

    /* --------------------------------------------------------------------------------------------------------------------*/
    /* Теперь нужно создать цифровую подпись нашего msg */
    /* --------------------------------------------------------------------------------------------------------------------*/

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
    bc_sha256(digest, msg, msg_len);
                                
    // 2.1.1 Печатаем хэш
    printf("Calculated digest is:\n");
                                                
    for (i = 0; i < 32; i++) {
	printf("%.2x",digest[i]);
    }
    printf("\n\n");

    // 2.2 Вычисляем сигнатуру и выводим на экран
    signature = ECDSA_do_sign(digest, sizeof(digest), key);
    printf("Calculated signature is:\n");
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));


    free(der);
    ECDSA_SIG_free(signature);    

    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(bn_priv_1);
                            
    EC_KEY_free(key);

    // -----------------------------------------------------------
    free(msg);
    bc_txout_destroy(&outs[0]);
    bc_txout_destroy(&outs[1]);
    bc_txout_destroy(&prev_outs[0]);
    bc_txin_destroy(&ins_sign[0]);

    return 0;
}
