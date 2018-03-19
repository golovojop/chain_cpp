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


    const char addr_rcv[]	= "617078891a7529b047c4478a4fef6cffa06ca3dd";	// Это hash160(raw_public_key)
    const char addr_my[] 	= "5add5c3a100e4ff2aa740fd76cb92a703479c92e";


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
    
    
    printf("tx.version: %d\n", tx.version);
    printf("inputs count: %d\n", tx.inputs_count);
    bc_print_hex("tx.inputs[0].outpoint.txid: ", tx.inputs[0].outpoint.txid, 32);
    printf("tx.inputs[0].outpoint.index: %d\n", tx.inputs[0].outpoint.index);
    printf("tx.inputs[0].script_len: %llx\n", tx.inputs[0].script_len);
    bc_print_hex("tx.inputs[0].script: ", tx.inputs[0].script, tx.inputs[0].script_len);

    printf("tx.outputs[0].value: %d\n", tx.outputs[0].value);
    printf("tx.outputs[0].script_len: %d\n", tx.outputs[0].script_len);
    bc_print_hex("tx.outputs[0].script: ", tx.outputs[0].script, tx.outputs[0].script_len);

    printf("tx.outputs[1].value: %d\n", tx.outputs[1].value);
    printf("tx.outputs[1].script_len: %d\n", tx.outputs[1].script_len);
    bc_print_hex("tx.outputs[1].script: ", tx.outputs[1].script, tx.outputs[0].script_len);

    msg_len = bc_tx_size(&tx, BC_SIGHASH_ALL);
    msg = malloc(msg_len);
    bc_tx_serialize(&tx, msg, BC_SIGHASH_ALL);

    printf("msg len: %d\n", msg_len);
    bc_print_hex("msg      ", msg, msg_len);
    printf("msg (exp): %s\n", msg_exp);

    free(msg);
    bc_txout_destroy(&outs[0]);
    bc_txout_destroy(&outs[1]);
    bc_txout_destroy(&prev_outs[0]);
    bc_txin_destroy(&ins_sign[0]);

    return 0;
}