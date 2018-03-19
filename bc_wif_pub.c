#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "./h/base58.h"
#include "./h/hash.h"


#define	KEY_PRIV_SIZE 	32
#define KEY_WIF_SIZE	34
#define P2PKH_SIZE	25
#define KEY_PUB_COMP	1
#define KEY_PRIV_T3	0xef
#define KEY_PUB_T3	0x6f
#define BUF_SIZE	256

#define INPUT_OK       	0
#define INPUT_BAD	1

// ------------------------------------------------------------------------------------------

int getLine(char *prmpt, char *buff, size_t len) {

    memset(buff, 0, len);
    
    printf ("%s", prmpt);
    fflush (stdout);
    
    if(fgets (buff, len, stdin) == NULL) {
	printf("err: No input\n");
	return INPUT_BAD;
    }
    
    // Важно, нужно убрать символ конца строки, иначе перекодировка не будет работать
    if(buff[strlen(buff) - 1] == '\n'){
      buff[strlen(buff) - 1] = 0;
    }
    
    return INPUT_OK;

}

// ------------------------------------------------------------------------------------------
void print_bytes(const char * Header, uint8_t * array, int len){

    printf(Header);
    for (int i = 0; i < len; i++) {
	printf("%.2x", array[i]);
    }
    printf("\n");
}

/*
Адрес кошелька - это P2PKH address закодированный в Base58Check.
Напомню, из чего состоит P2PKH:

01 byte 	- version (00 or 6f)
20 bytes	- hash160 of raw public key
04 bytes 	- checksum

Итого - 25 байтов
*/

int main(){

    printf("\n\nWallet address to Public key decoder.\n\n");

    
    // --------------------------------------------------------------------------------------
    // 2.1 Прочитать адрес кошелька
    
    char * wallet = calloc(BUF_SIZE, sizeof(char));
    uint8_t wallet_bytes[P2PKH_SIZE];
    
    if(INPUT_BAD == getLine("Enter Wallet address:   ", wallet, BUF_SIZE)){
      return 1;
    }
    
    printf("\nYour wallet address is: %s\n", wallet);

    // 2.2 Декодируем WIF, чтобы снова получить приватный ключ
    BIGNUM *bn_wallet = BN_new();
    int nDecoded =  bc_base58_decode(bn_wallet, (const char *)wallet, strlen(wallet));
    
    if(!nDecoded){
      printf("Can't decode address to key\n");
      return 1;
    }
    
    memset(wallet_bytes, 0, P2PKH_SIZE);
    BN_bn2bin((const BIGNUM *)bn_wallet, wallet_bytes);
    print_bytes("\nDecoded Base58Check:\n", wallet_bytes, P2PKH_SIZE);
    print_bytes("\nDecoded P2PKH      :\n", wallet_bytes + 1, P2PKH_SIZE - 5);

    BN_clear_free(bn_wallet);
    free(wallet);
    return 0;
}
