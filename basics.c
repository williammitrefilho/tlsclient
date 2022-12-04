#include <stdio.h>
#include <basics.h>

const unsigned char hx_label[2] = {'H', 'X'};
const unsigned char hx_chars[16] = {
    
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'A', 'B',
    'C', 'D', 'E', 'F'
};

unsigned char charval(unsigned char c){
    
    return (c - 0x30)*(c >= 0x30 && c <= 0x39)
            | (c - 0x37)*(c >= 0x41 && c <= 0x46)
            | (c - 0x57)*(c >= 0x61 && c <= 70);
}

unsigned short printchars(unsigned char *data, unsigned short data_len){
    
    for(int i = 0; i < data_len; i++){
        
        printf("%c", data[i]);
    }
    return 0;
}

unsigned short printhex(unsigned char *data, unsigned short data_len){
    
    for(int i = 0; i < data_len; i++){
        
        printf("%02X", data[i]);
    }
    return 0;
}

unsigned short hex2bin(unsigned char* data, unsigned char* out, unsigned short *out_len){
    
    unsigned short idx = 0;
    while(data[idx] != 0){
        
        if(out){
            
            out[idx/2] = (charval(data[idx++]) << 4 | data[idx++]);
        }
        else{
            
            idx += 2;
        }
    }
    *out_len = idx/2;
    return 0;
}

void printbhex(unsigned char *data, unsigned short len){
    
    for(int i = 0; i < len; i++){
    
        if(i%32== 0)
            printf("\n");
            
        printf("%02X", data[i]);    
    }
}

unsigned short bin2hex(unsigned char *data, unsigned short data_len, unsigned char *out){
    
    for(int i = 0; i < data_len;  i++){
        
        out[2*i] = hx_chars[data[i] >> 4];
        out[2*i+1] = hx_chars[data[i] & 0x0F];
    }
    return 0;
}
