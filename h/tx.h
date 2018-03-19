#ifndef __TX_H
#define __TX_H

#include <stdint.h>
#include "common.h"
#include "endian.h"
#include "varint.h"

typedef struct {
    uint64_t value;
    uint64_t script_len;	// varint for serialization
    uint8_t *script;
} bc_txout_t;

typedef struct {
    uint8_t txid[32];
    uint32_t index;
} bc_outpoint_t;

typedef struct {
    bc_outpoint_t outpoint;
    uint64_t script_len;	// varint for serialization
    uint8_t *script;
    uint32_t sequence;
} bc_txin_t;

typedef struct {
    uint32_t version;
    uint64_t inputs_count;	// varint for serialization
    bc_txin_t *inputs;
    uint64_t outputs_count;	// varint for serialization
    bc_txout_t *outputs;
    uint32_t locktime;
} bc_tx_t;

typedef enum {
    BC_SIGHASH_ALL = 0x01
} bc_sighash_t;

typedef uint8_t *bc_message_t;

// Заполнить данными структуру outpoint_t
void bc_outpoint_fill(bc_outpoint_t *outpoint, const char *txid, uint32_t index) {
    bc_parse_hex(outpoint->txid, txid);
    bc_reverse(outpoint->txid, 32);
    outpoint->index = bc_eint32(BC_LITTLE, index);
}


void bc_txout_create_p2pkh(bc_txout_t *txout, const uint64_t value, const char *hash160) {
    char script[52] = { 0 };
    
//	Формируем строковое представление скрипта    
//	0x76	OP_DUP
//	0xa9	OP_HASH160
//	0x14	[ hash160 ]
//	0x88	OP_EQUALVERIFY
//	0xac	OP_CHECKSIG    
    sprintf(script, "76a914%s88ac", hash160);
    txout->value = bc_eint64(BC_LITTLE, value);
    
//	Строковое представление скрипта превращаем в байтовый массив опкодов. При этом
//	0x76 становится младшим байтом массива, соответственно и обработан будет как
//	первая инструкция скрипта.
    txout->script = bc_alloc_hex(script, (size_t *)&txout->script_len);
}

void bc_txout_destroy(bc_txout_t *txout) {
    free(txout->script);
}

void bc_txin_create_p2pkh(	bc_txin_t *txin,
				const bc_outpoint_t *outpoint,
    				const char *sig,
    				const char *pub,
    				bc_sighash_t flag) {

    char script[400] = { 0 };

    /*
	Здесь весь скрипт формируется в строковом представлении. Фактически получаем строку из
	шестнадцатеричных цифр (hex-строку). Затем эта строка будет сконвертирована в байты.
	
	strlen(sig)/2 + 1	Размер сигнатуры в байтах плюс один байт для флага SIGHASH_ALL.
				Фактически это опкод команды push N-bytes
	sig			Сама сигнатура
	flag			Флаг SIGHASH_ALL
	strlen(pub)/2		Размер публичного ключа в байтах. Фактически опкод команды push N-bytes
	pub			Сам публичный ключ
    */
    sprintf(script, "%02lx%s%02x%02lx%s", strlen(sig) / 2 + 1, sig, flag, strlen(pub) / 2, pub);

    memcpy(&txin->outpoint, outpoint, sizeof(bc_outpoint_t));
    // Конвертируем hex-строку в байты
    txin->script = bc_alloc_hex(script, (size_t *)&txin->script_len);
    txin->sequence = 0xffffffff;
}

void bc_txin_destroy(bc_txin_t *txin) {
    free(txin->script);
}

/* signable message */

void bc_txin_create_signable(bc_txin_t *txin, const bc_outpoint_t *outpoint, const bc_txout_t *utxo) {
    memcpy(&txin->outpoint, outpoint, sizeof(bc_outpoint_t));
    
    txin->script_len = utxo->script_len;
    txin->script = malloc(utxo->script_len);
    memset(txin->script, 0, utxo->script_len);
    memcpy(txin->script, utxo->script, utxo->script_len);
    txin->sequence = 0xffffffff;
}

void bc_txin_create_truncated(bc_txin_t *txin, const bc_outpoint_t *outpoint) {
    memcpy(&txin->outpoint, outpoint, sizeof(bc_outpoint_t));
    txin->script_len = 0;
    txin->script = NULL;
    txin->sequence = 0xffffffff;
}

size_t bc_tx_size(const bc_tx_t *tx, bc_sighash_t flag) {
    size_t size = 0;
    int i;
//    printf("\n\nsize = %d\n", size);


    /* version */
    size += sizeof(uint32_t);
//    printf("size += sizeof(uint32_t) = %d\n", size);

    /* inputs count */
    size += bc_varint_size(tx->inputs_count);
//    printf("size += bc_varint_size(tx->inputs_count) = %d\n", size);


    /* inputs */
    for (i = 0; i < tx->inputs_count; i++) {
        bc_txin_t *txin = &tx->inputs[i];

        /* outpoint */
        size += sizeof(bc_outpoint_t);
	//printf("size += sizeof(bc_outpoint_t) = %d\n", size);

        /* script */
        size += bc_varint_size(txin->script_len);
	//printf("size += bc_varint_size(txin->script_len) = %d\n", size);
        
        size += txin->script_len;
	//printf("size += txin->script_len = %d\n", size);

        /* sequence */
        size += sizeof(uint32_t);
    }

    /* outputs count */
    size += bc_varint_size(tx->outputs_count);

    /* outputs */
    for (i = 0; i < tx->outputs_count; ++i) {
        bc_txout_t *txout = &tx->outputs[i];

        /* value */
        size += sizeof(uint64_t);

        /* script */
        size += bc_varint_size(txout->script_len);
        size += txout->script_len;
    }

    /* locktime */
    size += sizeof(uint32_t);

    if (flag) {

        /* sighash */
        size += sizeof(uint32_t);
    }

    return size;
}

void bc_tx_serialize(const bc_tx_t *tx, uint8_t *raw, bc_sighash_t flag) {
    uint8_t *ptr;
    size_t varlen;
    int i;

    ptr = raw;

    /* version */
    *(uint32_t *)ptr = bc_eint32(BC_LITTLE, tx->version);
    ptr += sizeof(uint32_t);

    /* inputs count */
    bc_varint_set(ptr, tx->inputs_count, &varlen);
    ptr += varlen;

    /* inputs */
    for (i = 0; i < tx->inputs_count; ++i) {
        bc_txin_t *txin = &tx->inputs[i];

        /* outpoint */
        memcpy(ptr, txin->outpoint.txid, 32);
        ptr += 32;
        *(uint32_t *)ptr = bc_eint32(BC_LITTLE, txin->outpoint.index);
        ptr += sizeof(uint32_t);

        /* script */
        bc_varint_set(ptr, txin->script_len, &varlen);
        ptr += varlen;
        memcpy(ptr, txin->script, txin->script_len);
        ptr += txin->script_len;

        /* sequence */
        *(uint32_t *)ptr = bc_eint32(BC_LITTLE, txin->sequence);
        ptr += sizeof(uint32_t);
    }

    /* outputs count */
    bc_varint_set(ptr, tx->outputs_count, &varlen);
    ptr += varlen;

    /* outputs */
    for (i = 0; i < tx->outputs_count; ++i) {
        bc_txout_t *txout = &tx->outputs[i];

        /* value */
        *(uint64_t *)ptr = bc_eint64(BC_LITTLE, txout->value);
        ptr += sizeof(uint64_t);

        /* script */
        bc_varint_set(ptr, txout->script_len, &varlen);
        ptr += varlen;
        memcpy(ptr, txout->script, txout->script_len);
        ptr += txout->script_len;
    }

    /* locktime */
    *(uint32_t *)ptr = bc_eint32(BC_LITTLE, tx->locktime);
    ptr += sizeof(uint32_t);

    if (flag) {

        /* sighash */
        *(uint32_t *)ptr = bc_eint32(BC_LITTLE, flag);
    }
}

#endif
