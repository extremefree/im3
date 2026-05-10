#include <string.h>
#include <stdio.h>
void chacha20_encrypt(unsigned char *out, const unsigned char *in, int len,
                      const unsigned char *key, const unsigned char *nonce, long long ctr);
int main(void){
    unsigned char key[32] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                              0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
                              0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
                              0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20};
    unsigned char nonce[8] = {0};
    unsigned char plain[] = "charlie\0ch123";
    unsigned char cipher[14] = {0};
    unsigned char decrypted[14] = {0};
    int len = 14;
    /* encrypt */
    chacha20_encrypt(cipher, plain, len, key, nonce, 0);
    printf("cipher: "); for(int i=0;i<len;i++) printf("%02x",cipher[i]); printf("\n");
    /* decrypt (same function) */
    chacha20_encrypt(decrypted, cipher, len, key, nonce, 0);
    printf("decrypted: ");
    for(int i=0;i<len;i++){
        if(decrypted[i]>=' ' && decrypted[i]<127) printf("%c",decrypted[i]);
        else printf("\\x%02x",decrypted[i]);
    }
    printf("\n");
    int ok = (memcmp(plain, decrypted, len)==0);
    printf("%s\n", ok?"MATCH":"MISMATCH");
    return !ok;
}
