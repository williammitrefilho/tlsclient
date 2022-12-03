gcc -I "include" -c sha.c -o bins/sha.o
gcc -I "include" -c aes.c -o bins/aes.o
gcc -I "include" -c cbc.c -o bins/cbc.o
gcc -I "include" -c tlsbase.c -o bins/tlsbase.o
gcc -I "include" -c socketimpl.c -o bins/socketimpl.o
gcc -I "include" -c p256.c -o bins/p256.o
gcc -I "include" -c x25519.c -o bins/x25519.o
gcc -I "include" -c prf.c -o bins/prf.o
gcc -I "include" -c basics.c -o bins/basics.o
gcc -I "include" -c ber_entity.c -o bins/ber_entity.o
gcc -I "include" -c gcm.c -o bins/gcm.o
gcc -I "include" -c gzip.c -o bins/gzip.o
gcc -I "include" -c converters.c -o bins/converters.o
gcc -I "include" -c testtls.c -o bins/testtls.o

gcc bins/sha.o bins/aes.o bins/cbc.o bins/tlsbase.o bins/socketimpl.o bins/p256.o bins/x25519.o bins/bm256.o bins/prf.o bins/ber_entity.o bins/basics.o bins/gcm.o bins/gzip.o bins/converters.o bins/testtls.o -o tlsclient.exe -lws2_32 
