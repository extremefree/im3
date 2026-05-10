using System;
using System.Security.Cryptography;
class T {
    static void Main() {
        // Raw alice private key (unclamped) from RFC 7748 §6.1
        byte[] priv = {0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
                        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
                        0x19,0x83,0x90,0xa9,0x91,0x32,0xad,0xf0,
                        0x37,0xec,0xf7,0x06,0x55,0x06,0xd5,0xaa};
        try {
            var ecParam = new ECParameters {
                Curve = new ECCurve { Oid = new Oid("1.3.101.110") }
            };
        } catch(Exception e) { Console.WriteLine("ECParam: "+e.Message); }
        // Try X25519 via ECDiffieHellman
        try {
            var key = ECDiffieHellman.Create();
            Console.WriteLine("Key created: "+key.KeyExchangeAlgorithm);
        } catch(Exception e) { Console.WriteLine("Create: "+e.Message); }
    }
}
