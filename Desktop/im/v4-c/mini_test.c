#include <stdint.h>
#include <string.h>
#include <stdio.h>
void x25519(uint8_t*,const uint8_t*,const uint8_t*);
void x25519_base(uint8_t*,const uint8_t*);
int main(){
    /* direct call with alice_priv as both scalar and basepoint arg */
    static const uint8_t alice_priv[32]={
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0x19,0x83,0x90,0xa9,0x91,0x32,0xad,0xf0,
        0x37,0xec,0xf7,0x06,0x55,0x06,0xd5,0xaa
    };
    static const uint8_t base9[32]={9};
    uint8_t r1[32],r2[32];
    x25519_base(r1,alice_priv);
    x25519(r2,alice_priv,base9);
    printf("x25519_base: ");
    for(int i=0;i<32;i++) printf("%02x",r1[i]); printf("\n");
    printf("x25519(,9) : ");
    for(int i=0;i<32;i++) printf("%02x",r2[i]); printf("\n");
    printf("same: %d\n", memcmp(r1,r2,32)==0);
    return 0;
}
