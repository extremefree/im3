#include <string.h>
#include <stdio.h>
void x25519(unsigned char *out, const unsigned char *priv, const unsigned char *pub);
void x25519_base(unsigned char *pub, const unsigned char *priv);
int main(void){
    unsigned char ap[32]={0},ab[32]={0},bp[32]={0},bb[32]={0},sa[32]={0},sb[32]={0};
    ap[0]=1; ap[31]=0x40;
    bp[0]=2; bp[31]=0x40;
    x25519_base(ab, ap);
    x25519_base(bb, bp);
    x25519(sa, ap, bb);
    x25519(sb, bp, ab);
    int ok = (memcmp(sa,sb,32)==0);
    printf("sa: "); for(int i=0;i<8;i++) printf("%02x",sa[i]); printf("\n");
    printf("sb: "); for(int i=0;i<8;i++) printf("%02x",sb[i]); printf("\n");
    printf("%s\n", ok?"MATCH":"MISMATCH");
    return !ok;
}
