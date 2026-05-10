#include <string.h>
#include <stdio.h>
#include <stdlib.h>
void x25519(unsigned char *out, const unsigned char *priv, const unsigned char *pub);
void x25519_base(unsigned char *pub, const unsigned char *priv);

static void clamp(unsigned char *k) {
    k[0]  &= 0xF8;
    k[31] &= 0x7F;
    k[31] |= 0x40;
}

int main(int argc, char **argv){
    srand(argc > 1 ? atoi(argv[1]) : 42);
    int all_ok = 1;
    for (int t = 0; t < 100; t++) {
        unsigned char ap[32], bp[32], ab[32], bb[32], sa[32], sb[32];
        for (int i=0;i<32;i++) ap[i] = rand()&0xFF;
        for (int i=0;i<32;i++) bp[i] = rand()&0xFF;
        clamp(ap); clamp(bp);
        x25519_base(ab, ap);
        x25519_base(bb, bp);
        x25519(sa, ap, bb);
        x25519(sb, bp, ab);
        if (memcmp(sa,sb,32)!=0) {
            printf("MISMATCH at trial %d\n", t);
            printf("ap: "); for(int i=0;i<8;i++) printf("%02x",ap[i]); printf("...\n");
            printf("bp: "); for(int i=0;i<8;i++) printf("%02x",bp[i]); printf("...\n");
            printf("sa: "); for(int i=0;i<8;i++) printf("%02x",sa[i]); printf("...\n");
            printf("sb: "); for(int i=0;i<8;i++) printf("%02x",sb[i]); printf("...\n");
            all_ok = 0;
        }
    }
    puts(all_ok ? "ALL 100 MATCH" : "FAILURES FOUND");
    return !all_ok;
}
