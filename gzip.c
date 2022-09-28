// William Mitre Filho - 2022
// Uma implementação do algoritmo GZIP.
#include <stdio.h>
#include <gzip.h>

const unsigned char codes_translate[19] = {
    
    16, 17, 18, 0,
    8, 7, 9, 6,
    10, 5, 11, 4,
    12, 3, 13, 2,
    14, 1, 15
};

char searchCode(unsigned short *list, unsigned short len, unsigned short value){
    
    for(int i = 0; i < len; i++){
        
        if(list[i] == value)
            return i;
    }
    return -1;
}

long findNextSymbol(unsigned char *data, unsigned short data_len, unsigned short *byte_pos, unsigned char *bit_pos, unsigned short *codes, unsigned short n_codes, unsigned char *code_lengths){
    
    unsigned short byte = *byte_pos, code = 0;
    unsigned char bit = *bit_pos, code_len = 0;
    
    while(byte < data_len){
             
        if(bit > 7){
            
            byte++;
            bit = 0;
//            printf("%02X ", data[byte]);
        }
//        printf("%d, %d, %02X, %d\n", byte, bit, data[byte], data_len);
        code <<= 1;
        code |= (data[byte] >> bit++) & 1;
        code_len++;
/*        printf("code: ");
        for(int j = 0; j < 16; j++){
            
            printf("%d", (code >> (15 - j)) & 1);
        }
        printf("\n");*/
        if(code_len > 14){
            
//            printf("erro -> ");
//            printf("code: ");
            for(int j = 0; j < 16; j++){
                
//                printf("%d", (code >> (15 - j)) & 1);
            }
//            printf("\n");
            return -20;
        }
        for(long i = 0; i < n_codes; i++){
                
            if(code_lengths[i] == code_len){
                
                unsigned short mask = 0 - 1 - (0 - (1 << code_len));
                if(code == (codes[i] & mask)){
    /*                    
                    printf("%d code: ", i);
                    for(int j = 0; j < 16; j++){
                        
                        printf("%d", (code >> (15 - j)) & 1);
                    }
                    printf("\n");
    */                    
                    *byte_pos = byte;
                    *bit_pos = bit;
//                    printf("\nMatch:[%c](%02X)\n\n", codes[i], codes[i]);
                    return i;
                }
            }
        }
    }
    *byte_pos = byte;
    *bit_pos = bit;
    return -1;
}

unsigned short huffmanCodes(unsigned char* lengths, unsigned short lengths_len, unsigned short *codes){
    
    unsigned short lenchars[14], next_code = 0, next_codes[14];
    for(int i = 0; i < 14; i++){
        
        lenchars[i] = 0;
    }
    
    for(int i = 0; i < lengths_len; i++){
        
        lenchars[lengths[i]]++;
    }
    unsigned short idx = 0;
    for(int i = 1; i < 14; i++){
        
        next_code += lenchars[i - 1];
        next_code <<= 1;
        next_codes[i] = next_code;
//        printf("[%d]nextcode:%d\n", i, next_codes[i]);
    }
    for(int i = 0; i < lengths_len; i++){
        
        codes[i] = next_codes[lengths[i]]++;
/*        if(lengths[i] > 0){
            
            printf("[%c]code: ", i);
            for(int j = 0; j < lengths[i]; j++){
                
                printf("%d", (codes[i] >> (lengths[i] - 1 - j)) & 1);
            }
            printf("\n");
        }*/
    }
//    printf("\n");
    return 0;
}

unsigned short gzDecode(unsigned char *data, unsigned short data_len, unsigned short *literal_codes, unsigned short *dist_codes,
                            unsigned short *o_literal_lengths, unsigned short *o_dist_lengths, unsigned char *literal_lengths, unsigned char *dist_lengths,
                            unsigned short *o_byte_pos, unsigned char *o_bit_pos){
    
    if(data[0] != 0x1F || data[1] != 0x8B){
        
        return 1;
    }
    else if(data[2] != 0x08){
        
        return 2;
    }
    else if(data[3]){
        
        return 3;
    }
    unsigned char cm = (data[10] >> 1) & 0x03;
//    printf("compression method:%d\n", cm);
    if(cm != 2){
        
        return 4;
    }
    unsigned short literals = (data[10] >> 3) + 257;
    unsigned short distances = (data[11] & 0x1F) + 1;
    
    *o_literal_lengths = literals;
    *o_dist_lengths = distances;
    
    unsigned short codes_len = (data[11] >> 5 | ((data[12] & 1) << 3)) + 4;
//    printf("LIT:%d\nDIST:%d\nCODE:%d\n", literals, distances, codes_len);
    if(!dist_codes || !literal_codes){
        
        return 0;
    }
    
    unsigned short byte = 12, codes[19];
    unsigned char bit = 1, lengths[19];
    for(int i = 0; i < 19; i++){
        
        lengths[i] = 0x00;
        codes[i] = 0x00;
    }
    
    for(int i = 0; i < codes_len; i++){
        
        unsigned char ccode = 0;
        for(int j = 0; j < 3; j++){
            
            if(bit > 7){
                
                byte++;
                bit = 0;
            }
            ccode |= ((data[byte] >> bit++) & 1) << j;
        }
        lengths[codes_translate[i]] = ccode;
//        printf("[%d]length:%d\n", codes_translate[i], lengths[codes_translate[i]]);
    }
    huffmanCodes(lengths, 19, codes);
    for(int i = 0; i < 19; i++){
        
//        printf("%d code: ", i);
        for(int j = 0; j < lengths[i]; j++){
            
//            printf("%d", (codes[i] >> (lengths[i] - j - 1)) & 1);
        }
//        printf("\n");
    }
    unsigned short lit_count = 0, code = 0, code_len = 0, dist_count = 0, *pcount = &lit_count;
    unsigned char *subject = literal_lengths;

    while((lit_count < literals || dist_count < distances) && byte < data_len){
    
        if(lit_count == literals){
            
            subject = dist_lengths;
            pcount = &dist_count;
        }
        if(bit > 7){
            
            byte++;
            bit = 0;
        }
        code <<= 1;
        code |= (data[byte] >> bit++) & 1;
        code_len++;
        char value = -1;
        for(int i = 0; i < 19; i++){
            
            if(lengths[i] == code_len){
                
                unsigned short mask = 0 - 1 - (0 - (1 << code_len));
                if(code == (codes[i] & mask)){
/*                    
                    printf("%d code: ", i);
                    for(int j = 0; j < 16; j++){
                        
                        printf("%d", (code >> (15 - j)) & 1);
                    }
                    printf("\n");
*/                    
                    value = i;
                    code = 0;
                    code_len = 0;
                    break;
                }
            }
        }
        if(value >= 0){
            
            unsigned short idx = *pcount;
//            printf(" found(%d)[%d]\n", value, idx);
            code = 0;
            if(value < 16){
                
                subject[idx++] = value;
                *pcount = idx;
            }
            else if(value == 16){
                
                unsigned char ccode = 0;
                for(int i = 0; i < 2; i++){
                    
                    if(bit > 7){
                        
                        bit = 0;
                        byte++;
                    }
                    ccode |= ((data[byte] >> bit++) & 1) << i; 
                }
                for(int i = 0; i < 3+ccode; i++){
                    
                    subject[idx] = subject[idx - 1];
                    idx++;
                }
                *pcount = idx;
            }
            else if(value == 17){
                
                unsigned char ccode = 0;
                for(int i = 0; i < 3; i++){
                    
                    if(bit > 7){
                        
                        bit = 0;
                        byte++;
                    }
                    ccode |= ((data[byte] >> bit++) & 1) << i; 
                }
                for(int i = 0; i < 3+ccode; i++){
                    
                    subject[idx++] = 0;
                }
                *pcount = idx;
            }
            else if(value == 18){
                
                unsigned char ccode = 0;
                for(int i = 0; i < 7; i++){
                    
                    if(bit > 7){
                        
                        bit = 0;
                        byte++;
                    }
                    ccode |= ((data[byte] >> bit++) & 1) << i; 
                }
//                printf("qtd:%d\n", ccode);
                for(int i = 0; i < 11+ccode; i++){
                    
                    subject[idx++] = 0;
                }
                *pcount = idx;
            }
        }
    }
/*    
    for(int i = 0; i < lit_count; i++){
        
        printf("[%c] codeLen = %d\n", i, literal_lengths[i]);
    }
    for(int i = 0; i < dist_count; i++){
        
        printf("[%c] DcodeLen = %d\n", i, dist_lengths[i]);
    }
*/
    huffmanCodes(literal_lengths, lit_count, literal_codes);
    huffmanCodes(dist_lengths, dist_count, dist_codes);
   
    *o_byte_pos = byte;
    *o_bit_pos = bit;
    return 0;
}

unsigned short gzDeflate(unsigned char *data, unsigned short data_len, unsigned char *decomp, unsigned short max_decomp_len, unsigned short *decompressed_len){
    
    unsigned short literal_len  = 0, dist_len = 0;
    gzDecode(data, data_len, 0, 0, &literal_len, &dist_len, 0, 0, 0, 0);
    
    unsigned short literal_codes[literal_len], dist_codes[dist_len], byte_pos = 0, code = 0, idx = 0;
    unsigned char literal_lengths[literal_len], dist_lengths[dist_len], bit_pos = 0, code_len = 0;
    gzDecode(data, data_len, literal_codes, dist_codes, &literal_len, &dist_len, literal_lengths, dist_lengths, &byte_pos, &bit_pos);
    
    while(byte_pos < data_len){
    
        if(bit_pos > 7){
            
            byte_pos++;
            bit_pos = 0;
        }
        
        long value = findNextSymbol(data, data_len, &byte_pos, &bit_pos, literal_codes, literal_len, literal_lengths);
//        printf("pos:%d, val:%d\n", byte_pos, value);
        if(value < 0)
            return 1;
        if(value >= 0){
            
//            printf("found:%d\n", value);
            long len = -1;
//            printf(" found(%d)[%d]\n", value, idx);
            code = 0;
            if(value < 256){
            
//                printf("%c", value);
                if(decomp){
                    
//                    printf("%d", decomp);
                    if(idx == max_decomp_len)
                        break;
                        
                    decomp[idx] = value;
                }
                idx++;
            }
            else if(value < 257){
                
                *decompressed_len = idx;
//                printf("EOD\n");    
                break;
            }
            else{
            
//                printf("outro\n");
                unsigned short ccode = 0;
                if(value < 265){
                    
                    len = 3 + value - 257;
                }
                else if(value < 269){
                    
                    len = 11 + 2*(value - 265);
                    
                    for(int i = 0; i < 1; i++){
                        
                        if(bit_pos > 7){
                            
                            bit_pos = 0;
                            byte_pos++;
                        }
                        ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                    }
                    len += ccode;
                }
                else if(value < 273){
                    
                    len = 19 + 4*(value - 269);
                    for(int i = 0; i < 2; i++){
                        
                        if(bit_pos > 7){
                            
                            bit_pos = 0;
                            byte_pos++;
                        }
                        ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                    }
                    len += ccode;                    
                }
                else if(value < 277){
                    
                    len = 35 + 8*(value - 273);
                    for(int i = 0; i < 3; i++){
                        
                        if(bit_pos > 7){
                            
                            bit_pos = 0;
                            byte_pos++;
                        }
                        ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                    }
                    len += ccode;    
                }
                else if(value < 281){
                    
                    len = 67 + 16*(value - 277);
                    for(int i = 0; i < 4; i++){
                        
                        if(bit_pos > 7){
                            
                            bit_pos = 0;
                            byte_pos++;
                        }
                        ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                    }
                    len += ccode;    
                }
                else if(value < 285){
                    
                    len = 131 + 32*(value - 281);
                    for(int i = 0; i < 5; i++){
                        
                        if(bit_pos > 7){
                            
                            bit_pos = 0;
                            byte_pos++;
                        }
                        ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                    }
                    len += ccode;    
                }
                else{
                    
                    len = 258;
                }
//                printf("ref!%d\n", len);                
            }
            if(len >= 0){
                
                int distance = findNextSymbol(data, data_len, &byte_pos, &bit_pos, dist_codes, dist_len, dist_lengths);
                if(distance >= 0){
                    
                    unsigned short distn = 0, ccode = 0;
                    if(distance < 4){
                        
                        distn = distance + 1;
                    }
                    else if(distance < 6){
                        
                        distn = 5 + 2*(distance - 4);
                    
                        for(int i = 0; i < 1; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 8){
                        
                        distn = 9 + 4*(distance - 6);
                    
                        for(int i = 0; i < 2; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 10){
                        
                        distn = 17 + 8*(distance - 8);
                    
                        for(int i = 0; i < 3; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 12){
                        
                        distn = 33 + 16*(distance - 10);
                    
                        for(int i = 0; i < 4; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 14){
                        
                        distn = 65 + 32*(distance - 12);
                    
                        for(int i = 0; i < 5; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 16){
                        
                        distn = 129 + 64*(distance - 14);
                    
                        for(int i = 0; i < 6; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 18){
                        
                        distn = 257 + 128*(distance - 16);
                    
                        for(int i = 0; i < 7; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 20){
                        
                        distn = 513 + 256*(distance - 18);
                    
                        for(int i = 0; i < 8; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 22){
                        
                        distn = 1025 + 512*(distance - 20);
                    
                        for(int i = 0; i < 9; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 24){
                        
                        distn = 2049 + 1024*(distance - 22);
                    
                        for(int i = 0; i < 10; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 26){
                        
                        distn = 4097 + 2048*(distance - 24);
                    
                        for(int i = 0; i < 11; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 28){
                        
                        distn = 8193 + 4096*(distance - 26);
                    
                        for(int i = 0; i < 12; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
                    else if(distance < 30){
                        
                        distn = 16385 + 8192*(distance - 28);
                    
                        for(int i = 0; i < 13; i++){
                            
                            if(bit_pos > 7){
                                
                                bit_pos = 0;
                                byte_pos++;
                            }
                            ccode |= ((data[byte_pos] >> bit_pos++) & 1) << i; 
                        }
                        distn += ccode;    
                    }
//                    printf("[r:-%d, %d]", distn, len);
                    unsigned short nidx = idx - distn;
                    for(int i = 0; i < len; i++){
                        
                        if(decomp){
                            if(idx == max_decomp_len){
                            
                                break;
                            }
                            decomp[idx] = decomp[nidx];
//                            printf("%c", decomp[nidx]);
                        }
                        nidx++; idx++;
                    }
                }                                   
            }
        }
    }      
    return 0;
}