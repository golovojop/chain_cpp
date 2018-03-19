#include "./h/common.h"
#include "./h/endian.h"
#include "./h/tx.h"
#include "./h/hash.h"
#include "./h/ec.h"

int main() {
    bc_txout_t outs[2];
    bc_txout_t prev_outs[1];
    bc_txin_t ins_sign[1];
    bc_outpoint_t outpoint;
    bc_tx_t tx;
    uint8_t *msg;
    size_t msg_len;

    const char msg_exp[] = "0100000001f3a27f485f9833c8318c490403307fef1397121b5dd8fe70777236e7371c4ef3000000001976a9146bf19e55f94d986b4640c154d86469934191951188acffffffff02e0fe7e01000000001976a91418ba14b3682295cb05230e31fecb00089240660888ace084b003000000001976a9146bf19e55f94d986b4640c154d86469934191951188ac0000000001000000";

    /* */

    /* Создать output 1 на (0.251 BTC) */
    bc_txout_create_p2pkh(&outs[0], 25100000, "18ba14b3682295cb05230e31fecb000892406608");

    /* Создать output 2 на (change, 0.619 BTC) */
    bc_txout_create_p2pkh(&outs[1], 61900000, "6bf19e55f94d986b4640c154d864699341919511");

    /* input from utxo (0.87 BTC) */
    bc_outpoint_fill(&outpoint, "f34e1c37e736727770fed85d1b129713ef7f300304498c31c833985f487fa2f3", 0);
    bc_txout_create_p2pkh(&prev_outs[0], 87000000, "6bf19e55f94d986b4640c154d864699341919511");
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

    /* */

    bc_print_hex("outs[0].script", outs[0].script, outs[0].script_len);
    bc_print_hex("outs[1].script", outs[1].script, outs[1].script_len);
    puts("");
    bc_print_hex("ins_sign[0].outpoint.txid", ins_sign[0].outpoint.txid, 32);
    printf("ins_sign[0].outpoint.index: %u\n", ins_sign[0].outpoint.index);
    bc_print_hex("ins_sign[0].script", ins_sign[0].script, ins_sign[0].script_len);
    puts("");
    bc_print_hex("msg      ", msg, msg_len);
    printf("msg (exp): %s\n", msg_exp);

    free(msg);
    bc_txout_destroy(&outs[0]);
    bc_txout_destroy(&outs[1]);
    bc_txout_destroy(&prev_outs[0]);
    bc_txin_destroy(&ins_sign[0]);

    return 0;
}

