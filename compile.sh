#
# Read here about ssl library
#
# https://stackoverflow.com/questions/13784434/gcc-use-openssls-sha256-functions
#

#gcc -o ./bc_serial_1 ./bc_serial_1.c
#gcc -o ./bc_tx_build_1 ./bc_tx_build_1.c -lssl -lcrypto
#gcc -o ./bc_hash_1 ./bc_hash_1.c -lssl -lcrypto
#gcc -o ./bc_keys_1 ./bc_keys_1.c -lssl -lcrypto -std=c99
#gcc -o ./bc_keys_2 ./bc_keys_2.c -lssl -lcrypto -std=c99
#gcc -o ./bc_sign_1 ./bc_sign_1.c -lssl -lcrypto -std=c99
#gcc -o ./bc_sign_2 ./bc_sign_2.c -lssl -lcrypto -std=c99
#gcc -o ./bc_wif_1 ./bc_wif_1.c -lssl -lcrypto -std=c99
#gcc -o ./bc_tx_1 ./bc_tx_1.c -lssl -lcrypto -std=c99
#gcc -o ./bc_tx_3 ./bc_tx_3.c -lssl -lcrypto -std=c99
#gcc -o ./bc_tx_4 ./bc_tx_4.c -lssl -lcrypto -std=c99
#gcc -o ./bc_tx_5 ./bc_tx_5.c -lssl -lcrypto -std=c99
#gcc -o ./bc_tx_ok ./bc_tx_ok.c -lssl -lcrypto -std=c99
#gcc -o ./bc_priv_to_pub ./bc_priv_to_pub.c -lssl -lcrypto -std=c99
#gcc -o ./bc_wif_2 ./bc_wif_2.c -lssl -lcrypto -std=c99
#gcc -o ./bc_wif_priv ./bc_wif_priv.c -lssl -lcrypto -std=c99
#gcc -o ./bc_wif_pub ./bc_wif_pub.c -lssl -lcrypto -std=c99
#gcc -o ./bc_wallet_1 ./bc_wallet_1.c -lssl -lcrypto -std=c99
gcc -o ./bc_wallet_tn ./bc_wallet_tn.c -lssl -lcrypto -std=c99
#gcc -o ./bc_wallet_mn ./bc_wallet_mn.c -lssl -lcrypto -std=c99
