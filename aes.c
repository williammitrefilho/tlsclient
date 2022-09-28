// William Mitre Filho - 2022
// Uma implementação do algoritmo de criptografia AES, conforme definido pelo NIST (https://doi.org/10.6028/NIST.FIPS.197)
#include <aes.h>

const unsigned char aes_sub_box[256] = {

    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char aes_inv_sub_box[256] = {

    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

unsigned short aes_multiply(unsigned char a, unsigned char b){

    unsigned short out = 0;
    for(int i=0; i < 8; i++){

        out ^= (a&(0-((b>>i) & 1)))<<i;
    }
    return out;
}


unsigned short aes_sub_bytes(unsigned char in[4][4]){

    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            in[i][j] = aes_sub_box[in[i][j]];
        }
    }
    return 0;
}

unsigned short aes_inv_sub_bytes(unsigned char in[4][4]){

    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            in[i][j] = aes_inv_sub_box[in[i][j]];
        }
    }
    return 0;
}

unsigned char aes_mod(unsigned short a){

    unsigned short out = a, divisor = 0x11b, mask;
    divisor <<= 7;
    for(int i=0; i < 8; i++){

        mask = 0-(((256 << (7-i))&out) >> (15-i));
        out ^= (divisor&mask >> i);
        divisor >>= 1;
    }
    return out&255;
}

unsigned char aes_multiply_mod(unsigned char a, unsigned char b){

    return aes_mod(aes_multiply(a, b));
}

unsigned short aes_shift_rows(unsigned char in[4][4]){

    unsigned char temp[4][4];
    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            temp[i][j] = in[i][(j+i)%4];
        }
    }
    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            in[i][j] = temp[i][j];
        }
    }
    return 0;
}

unsigned short aes_inv_shift_rows(unsigned char in[4][4]){

    unsigned char temp[4][4];
    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            temp[i][j] = in[i][(4+j-i)%4];
        }
    }
    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            in[i][j] = temp[i][j];
        }
    }
    return 0;
}

unsigned short aes_mix_columns(unsigned char a[4][4]){

    unsigned char aux[4][4];
    for(int i=0; i < 4; i++){

        aux[0][i] = aes_mm(0x02, a[0][i]) ^ aes_mm(0x03, a[1][i]) ^ a[2][i] ^ a[3][i];
        aux[1][i] = a[0][i] ^ aes_mm(0x02, a[1][i]) ^ aes_mm(0x03, a[2][i]) ^ a[3][i];
        aux[2][i] = a[0][i] ^ a[1][i] ^ aes_mm(0x02, a[2][i]) ^ aes_mm(0x03, a[3][i]);
        aux[3][i] = aes_mm(0x03, a[0][i]) ^ a[1][i] ^ a[2][i] ^ aes_mm(0x02, a[3][i]);
    }
    for(int i=0; i < 4; i++){

        for(int j = 0; j < 4; j++){

            a[i][j] = aux[i][j];
        }
    }
    return 0;
}

unsigned short aes_inv_mix_columns(unsigned char a[4][4]){

    unsigned char aux[4][4];
    for(int i=0; i < 4; i++){

        aux[0][i] = aes_mm(0x0e, a[0][i]) ^ aes_mm(0x0b, a[1][i]) ^ aes_mm(0x0d, a[2][i]) ^ aes_mm(0x09, a[3][i]);
        aux[1][i] = aes_mm(0x09, a[0][i]) ^ aes_mm(0x0e, a[1][i]) ^ aes_mm(0x0b, a[2][i]) ^ aes_mm(0x0d, a[3][i]);
        aux[2][i] = aes_mm(0x0d, a[0][i]) ^ aes_mm(0x09, a[1][i]) ^ aes_mm(0x0e, a[2][i]) ^ aes_mm(0x0b, a[3][i]);
        aux[3][i] = aes_mm(0x0b, a[0][i]) ^ aes_mm(0x0d, a[1][i]) ^ aes_mm(0x09, a[2][i]) ^ aes_mm(0x0e, a[3][i]);
    }
    for(int i=0; i < 4; i++){

        for(int j = 0; j < 4; j++){

            a[i][j] = aux[i][j];
        }
    }
    return 0;
}

unsigned short aes_rotword(unsigned char* a, unsigned char* out){

    unsigned char aux[4];
    for(int i=0; i < 4; i++){

        aux[i] = a[(i+1)%4];
    }
    memcpy(out, aux, 4);
    return 0;
}

unsigned short aes_key_expansion(unsigned char* key, unsigned short key_len, unsigned char* out){

    unsigned short n_rounds = key_len + 6, n_wordbytes = 16*(n_rounds+1), n_words = n_wordbytes/4;
    unsigned char k_w[n_wordbytes], temp[4], rcon[4] = {0x00, 0x00, 0x00, 0x00};
    unsigned long c;
    int i, j;
    for(i=0; i < key_len; i++){

        k_w[4*i] = key[4*i];
        k_w[4*i+1] = key[4*i+1];
        k_w[4*i+2] = key[4*i+2];
        k_w[4*i+3] = key[4*i+3];
    }
    for(i = key_len; i < n_words; i++){

        c = 0;
        for(j=0; j < 4; j++){

            temp[j] = k_w[4*(i-1)+j];
        };
        c = 0;
        if(!(i%key_len)){

            c = 1;
            aes_rotword(temp, temp);
            rcon[0] = aes_mod(1<<(i/key_len-1));
            for(j=0; j < 4; j++){

                temp[j] = aes_sub_box[temp[j]];
                temp[j] ^= rcon[j];
            }
        }
        else if(key_len > 6 && (i%key_len) == 4){

            for(j=0; j < 4; j++){

                temp[j] = aes_sub_box[temp[j]];
            }
        }
        for(j=0; j < 4; j++){

            k_w[4*i+j] = k_w[4*(i-key_len)+j] ^ temp[j];
            c |= c*(k_w[4*i+j] << (8*(3-j)));
        }
        if(c)
            c = 0;
    }

    for(i=0; i < n_words; i++){

        out[4*i] = k_w[4*i];
        out[4*i+1] = k_w[4*i+1];
        out[4*i+2] = k_w[4*i+2];
        out[4*i+3] = k_w[4*i+3];
    }
    return 0;
}

unsigned short aes_inv_key_expansion(unsigned char* key, unsigned short key_len, unsigned char* out){

    unsigned short n_rounds = key_len+6, n_wordbytes = 16*(key_len+7);
    unsigned char expanded_key[n_wordbytes];
    unsigned char temp_roundkey[4][4];
    unsigned short ttemp_roundkey[4][4];

    aes_key_expansion(key, key_len, expanded_key);
    for(int i=0; i < n_rounds+1; i++){

        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                temp_roundkey[k][j] = expanded_key[16*i+4*j+k];
                ttemp_roundkey[k][j] = temp_roundkey[k][j];
            }
        }
        aes_inv_mix_columns(temp_roundkey);
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                ttemp_roundkey[k][j] = temp_roundkey[k][j];
            }
        }
        if(!out)
            continue;
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                out[16*i+4*j+k] = temp_roundkey[k][j];
            }
        }
    }
    return 0;
}

unsigned short aes_encrypt(unsigned char *data, unsigned char *key, unsigned short key_len, unsigned char *out){

    unsigned short n_rounds = key_len+6, n_wordbytes = 16*(key_len+7);
    unsigned char expanded_key[n_wordbytes];
    aes_key_expansion(key, key_len, expanded_key);
    unsigned char state[4][4];
    unsigned short tstate[4][4];

    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            state[j][i] = data[4*i+j]^expanded_key[4*i+j];
            tstate[j][i] = state[j][i];
        }
    }

    for(int i=0; i < n_rounds; i++){

        aes_sub_bytes(state);
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                tstate[k][j] = state[k][j];
            }
        }
        aes_shift_rows(state);
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                tstate[k][j] = state[k][j];
            }
        }
        if(i < (n_rounds - 1)){

            aes_mix_columns(state);
            for(int j=0; j < 4; j++){

                for(int k=0; k < 4; k++){

                    tstate[k][j] = state[k][j];
                }
            }
        }
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                state[k][j] ^= expanded_key[16*(i+1)+4*j+k];
                tstate[k][j] = state[k][j];
                out[4*j+k] = state[k][j];
            }
        }
    }
    return 0;
}

unsigned short aes_decrypt(unsigned char *data, unsigned char *key, unsigned short key_len, unsigned char *out){

    unsigned short n_rounds = key_len+6, n_wordbytes = 16*(key_len+7);
    unsigned char expanded_key[n_wordbytes];
    aes_key_expansion(key, key_len, expanded_key);
    unsigned char state[4][4];
    unsigned short tstate[4][4];

    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            state[j][i] = data[4*i+j];
            tstate[j][i] = state[j][i];
        }
    }
    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            state[j][i] = data[4*i+j]^expanded_key[16*n_rounds+4*i+j];
            tstate[j][i] = state[j][i];
        }
    }
    int g = 0;

    for(int i=n_rounds-1; i >= 0; i--){

        aes_inv_shift_rows(state);
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                tstate[k][j] = state[k][j];
            }
        }
        aes_inv_sub_bytes(state);
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                tstate[k][j] = state[k][j];
            }
        }
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                tstate[k][j] = expanded_key[16*i+4*j+k];
            }
        }
        for(int j=0; j < 4; j++){

            for(int k=0; k < 4; k++){

                state[k][j] ^= expanded_key[16*i+4*j+k];
                tstate[k][j] = state[k][j];
            }
        }
        if(i > 0){

            aes_inv_mix_columns(state);
            for(int j=0; j < 4; j++){

                for(int k=0; k < 4; k++){

                    tstate[k][j] = state[k][j];
                }
            }
        }
    }
    for(int i=0; i < 4; i++){

        for(int j=0; j < 4; j++){

            out[4*i+j] = state[j][i];
        }
    }
    return 0;
}
