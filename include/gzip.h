#ifndef GZIP_H

#define GZIP_H

const unsigned char codes_translate[19];

long findNextSymbol(unsigned char *data, unsigned short data_len, unsigned short *byte_pos, unsigned char *bit_pos, unsigned short *codes, unsigned short n_codes, unsigned char *code_lengths);
char searchCode(unsigned short *list, unsigned short len, unsigned short value);
unsigned short huffmanCodes(unsigned char* lengths, unsigned short lengths_len, unsigned short *codes);
unsigned short gzDecode(unsigned char *data, unsigned short data_len, unsigned short *literal_codes, unsigned short *dist_codes, unsigned short *o_literal_lengths, unsigned short *o_dist_lengths, unsigned char *literal_lengths, unsigned char *dist_lengths, unsigned short *o_byte_pos, unsigned char *o_bit_pos);
unsigned short gzDeflate(unsigned char *data, unsigned short data_len, unsigned char *decomp, unsigned short max_decomp_len, unsigned short *decompressed_len);
#endif