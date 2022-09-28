#include <cbc.h>

unsigned short cbc_aes256_cbc(unsigned char iv[16], unsigned char key[32], unsigned char *msg, unsigned short msg_len, unsigned char *out){

    unsigned short n_blocks = (msg_len/16) + ((msg_len%16)>0);
    unsigned char state[16], iv_state[16], *pmsg = msg, *pout = out;
    memcpy(iv_state, iv, 16);
    for(int i = 0; i < n_blocks; i++){

        if((16*(i+1)) > msg_len){

            memcpy(state, pmsg, msg_len - 16*i);
        }
        else{

            memcpy(state, pmsg, 16);
        }
        for(int i = 0; i < 16; i++){

            state[i] ^= iv_state[i];
        }
        aes_encrypt(state, key, 8, state);
        memcpy(pout, state, 16);
        memcpy(iv_state, state, 16);
        pout += 16;
        pmsg += 16;
    }
    return 0;
}

unsigned short cbc_aes256_cbc_decrypt(unsigned char iv[16], unsigned char key[32], unsigned char *msg, unsigned short msg_len, unsigned char *out){

    unsigned short n_blocks = (msg_len/16) + (msg_len%16 > 0);
    unsigned char state[16], iv_state[16], *pmsg = msg, *pout = out;
    memcpy(iv_state, iv, 16);
    for(int i = 0; i < n_blocks; i++){

        if((16*(i+1)) > msg_len){

            memcpy(state, pmsg, msg_len - 16*i);
        }
        else{

            memcpy(state, pmsg, 16);
        }
        aes_decrypt(state, key, 8, state);
        for(int i = 0; i < 16; i++){

            state[i] ^= iv_state[i];
        }
        memcpy(iv_state, pmsg, 16);
        memcpy(pout, state, 16);
        pmsg += 16;
        pout += 16;
    }

    return 0;
}
