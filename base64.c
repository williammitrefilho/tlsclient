// William Mitre Filho - 2022
// Uma implementação de codificador e decodificador BASE64.
#include <stdio.h>
#include <base64.h>

const unsigned char base64_decode_chars[123] = {
    
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33
};

const unsigned char base64_encode_chars[64] = {
    
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

unsigned short base64_decode(unsigned char* str, unsigned short strlen, unsigned char *out){
    
    if(strlen % 4){
        
        return 1;
    }
    unsigned short symbol_len = strlen/4;
    unsigned int symbol = 0;
    
    for(int i = 0; i < symbol_len; i++){
        
//        printf("[%d(%d), %d(%d), %d(%d), %d(%d)] ", str[4*i], base64_decode_chars[str[4*i]], str[4*i+1], base64_decode_chars[str[4*i+1]], str[4*i+2], base64_decode_chars[str[4*i+2]], str[4*i+3], base64_decode_chars[str[4*i+3]]);
        symbol = (base64_decode_chars[str[4*i]] << 18)
                    |(base64_decode_chars[str[4*i+1]] << 12)
                    |(base64_decode_chars[str[4*i+2]] << 6)
                    | base64_decode_chars[str[4*i+3]];
                    
//        printf("%d\n", symbol);
        
        out[3*i] = symbol >> 16;
        out[3*i+1] = (symbol >> 8) & 0xff;
        out[3*i+2] = symbol & 0xff;
        
//        printf("(%d, %d, %d)\n", out[3*i], out[3*i+1], out[3*i+2]);
    }
    return 0;
}

unsigned short base64_encode(unsigned char *str, unsigned short strlen, unsigned char *out){
    
    
    unsigned char bit = 0;
    unsigned short byte = 0;
    unsigned short out_len = 4*(strlen/3 + ((strlen%3) > 0));
    int i;
    for(i = 0; i < out_len; i++){
        
        if(byte == strlen)
            break;
        
        if(bit == 0){
            
            out[i] = base64_encode_chars[str[byte] >> 2];
            bit = 6;
        }
        else if(bit == 6){
            
            out[i] = base64_encode_chars[((str[byte++] & 0x03) << 4) | (str[byte] >> 4)];
            bit = 4;
        }
        else if(bit == 4){
            
            out[i] = base64_encode_chars[((str[byte++] & 0x0F) << 2) | (str[byte] >> 6)];
            bit = 2;
        }
        else if(bit == 2){
            
            out[i] = base64_encode_chars[str[byte++] & 0x3F];
            bit = 0;
        }
    }
    while(i < out_len){
        
        out[i] = '=';
        i++;
    }
    return 0;   
}