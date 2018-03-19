#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include "./h/base58.h"
#include "./h/hash.h"


// Приватный ключ, который я получил с помощью OpenSSL.

uint8_t priv_bytes[32] = {
    0xea, 0xe3, 0xdb, 0x12, 0x0c, 0x5c, 0xf5, 0xc7,
    0x0f, 0x32, 0xad, 0x6c, 0xcd, 0xb4, 0x76, 0x94,
    0x45, 0x7c, 0x14, 0x4a, 0x20, 0x91, 0xa1, 0x8a,
    0xbd, 0xa3, 0xbc, 0xb2, 0xf0, 0x04, 0x22, 0x89 };

// Это тот же приватный ключ в строковом представлении
char priv_exp[] = "eae3db120c5cf5c70f32ad6ccdb47694457c144a2091a18abda3bcb2f0042289";

#define	KEY_PRIV_SIZE 	32
#define KEY_WIF_SIZE	34
#define KEY_PUB_COMP	1
#define KEY_PRIV_T3	0xef
#define KEY_PUB_T3	0x6f
#define BUF_WIF_SIZE	256

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

// ------------------------------------------------------------------------------------------

int main(){

    printf("\n\nWIF to Private key decoder\n\n");

    
    // --------------------------------------------------------------------------------------
    // 2.1 Создаем WIF (из приватного ключа)
    
    char * wif = calloc(BUF_WIF_SIZE, sizeof(char));
    uint8_t wif_bytes[KEY_WIF_SIZE];
    
    if(INPUT_BAD == getLine("Enter WIF: ", wif, BUF_WIF_SIZE)){
      return 1;
    }
    
    printf("\nYour WIF:  %s\n", wif);

    // 2.2 Декодируем WIF, чтобы снова получить приватный ключ
    BIGNUM *bn_wif = BN_new();
    int nDecoded =  bc_base58_decode(bn_wif, (const char *)wif, strlen(wif));
    
    if(!nDecoded){
      printf("Can't decode WIF to key\n");
      return 1;
    }
    
    memset(wif_bytes, 0, KEY_WIF_SIZE);
    BN_bn2bin((const BIGNUM *)bn_wif, wif_bytes);
    print_bytes("\nDecoded WIF:\n", wif_bytes, KEY_WIF_SIZE);
    print_bytes("\nDecoded private key:\n", wif_bytes + 1, KEY_WIF_SIZE - 2);

    BN_clear_free(bn_wif);
    free(wif);
    return 0;
}
