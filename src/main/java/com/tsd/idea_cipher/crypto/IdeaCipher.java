package com.tsd.idea_cipher.crypto;

public class IdeaCipher extends BlockCipher {

    private static final int KEY_SIZE = 16;
    private static final int BLOCK_SIZE = 8;
    private static final int ROUNDS = 8;

    private boolean encrypt;
    private int[] subKey;

    public IdeaCipher(String charKey, boolean encrypt) {
        super(KEY_SIZE, BLOCK_SIZE);
        this.encrypt = encrypt;
        setKey(charKey);
    }

    @Override
    protected void setKey(byte[] key) {
        int[] tempSubKey = generateSubkeys(key);
        if (encrypt) {
            subKey = tempSubKey;
        } else {
            subKey = invertSubkey(tempSubKey);
        }
    }

    @SuppressWarnings({"SuspiciousNameCombination", "PointlessArithmeticExpression"})
    @Override
    public void crypt(byte[] data, int offset) {
        // Impartiti blocul de date de 64 de biti in 4 sub blocuri de 16 biti
        int x1 = CrytoUtils.concat2Bytes(data[offset + 0], data[offset + 1]);
        int x2 = CrytoUtils.concat2Bytes(data[offset + 2], data[offset + 3]);
        int x3 = CrytoUtils.concat2Bytes(data[offset + 4], data[offset + 5]);
        int x4 = CrytoUtils.concat2Bytes(data[offset + 6], data[offset + 7]);
        // Ficare runda
        int k = 0; // subcheia index
        for (int round = 0; round < ROUNDS; round++) {
            int y1 = mul(x1, subKey[k++]);          // Multiplica X1 si prima subcheie
            int y2 = add(x2, subKey[k++]);          // Aduna X2 si a 2-a subcheie
            int y3 = add(x3, subKey[k++]);          // Aduna X3 si a 3-a subcheie
            int y4 = mul(x4, subKey[k++]);          // Multiplica X4 si a 4-a cheie
            int y5 = y1 ^ y3;                       // XOR rezultatul lui y1 si y3
            int y6 = y2 ^ y4;                       // XOR rezultatul lui y2 si y4
            int y7 = mul(y5, subKey[k++]);          // Multiplica rezultatul lui y5 cu a 5-a subcheie
            int y8 = add(y6, y7);                   // Aduna rezultatul lui y6 si y7
            int y9 = mul(y8, subKey[k++]);          // Multiplica rezultatul lui y8 cu cea de a 6-a subcheie
            int y10 = add(y7, y9);                  // Aduna rezultatul lui y7 si y9
            x1 = y1 ^ y9;                           // XOR rezultatul pasilor y1 si y9
            x2 = y3 ^ y9;                           // XOR rezultatul pasilor y3 si y9
            x3 = y2 ^ y10;                          // XOR rezultatul pasilor y2 si y10
            x4 = y4 ^ y10;                          // XOR rezultatul pasilor y4 si y10
        }
        // Transformarea finala a iesirii
        int r0 = mul(x1, subKey[k++]);              // Multiplica X1 si prima subcheie
        int r1 = add(x3, subKey[k++]);              // Aduna X2 si a 2-a subcheie
        int r2 = add(x2, subKey[k++]);              // Aduna X3 si a 3-a subcheie
        int r3 = mul(x4, subKey[k]);                // Multiplica X4 si a 4-a subcheie
        // Reatasarea celor 4 sub-blocuri
        data[offset + 0] = (byte) (r0 >> 8);
        data[offset + 1] = (byte) r0;
        data[offset + 2] = (byte) (r1 >> 8);
        data[offset + 3] = (byte) r1;
        data[offset + 4] = (byte) (r2 >> 8);
        data[offset + 5] = (byte) r2;
        data[offset + 6] = (byte) (r3 >> 8);
        data[offset + 7] = (byte) r3;
    }

    /**
     * Creating the subkeys from the user key. Crearea de subchei din cheia utilizatorului
     *
     * @param userKey 128-biti cheia utilizatorului
     * @return 52 16-biti cheia sublocurilor (6 pentru fiecare din cele 8 runde si inca 4 pentru transofrmarea iesirii)
     */ 
    private static int[] generateSubkeys(byte[] userKey) {
        if (userKey.length != 16) {
            throw new IllegalArgumentException();
        }
        int[] key = new int[ROUNDS * 6 + 4]; // 52 16-biti subchei

        // 128-biti userKey e impartit in sub-blocuri de 16-bit
        int b1, b2;
        for (int i = 0; i < userKey.length / 2; i++) {
            key[i] = CrytoUtils.concat2Bytes(userKey[2 * i], userKey[2 * i + 1]);
        }

        // Cheia e rotita 25 de biti in stanga si apoi impartita in 8 subchei
        // Primele 4 sunt folosite in 2 runde; ultimele 4 sunt folosite in runda 3
        // Cheia e rotita alti 25 biti la stanga pentru urmatorarele 8 subchei si asa mai departe.
        for (int i = userKey.length / 2; i < key.length; i++) {
            // It starts combining k1 shifted 9 bits with k2. This is 16 bits of k0 + 9 bits shifted from k1 = 25 bits
            // Incepe combinand k1 schimband 9 biti cu k2.
            b1 = key[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9;   // k1,k2,k3...k6,k7,k0,k9, k10...k14,k15,k8,k17,k18...
            b2 = key[(i + 2) % 8 < 2 ? i - 14 : i - 6] >>> 7;   // k2,k3,k4...k7,k0,k1,k10,k11...k15,k8, k9,k18,k19...
            key[i] = (b1 | b2) & 0xFFFF;
        }
        return key;
    }

    /**
     * Ele sunt fie inverse aditive sau multiplicative inverse ale subcheilor de criptare in ordine inversa
     *
     * @param subcheie subchei
     * @return inversat subchei
     */
    private static int[] invertSubkey(int[] subkey) {
        int[] invSubkey = new int[subkey.length];
        int p = 0;
        int i = ROUNDS * 6;
        // Pentru transformarea finala a iesirii 
        invSubkey[i]     = mulInv(subkey[p++]);     // 48 <- 0
        invSubkey[i + 1] = addInv(subkey[p++]);     // 49 <- 1
        invSubkey[i + 2] = addInv(subkey[p++]);     // 50 <- 2
        invSubkey[i + 3] = mulInv(subkey[p++]);     // 51 <- 3
        // De la runda 8 la 2
        for (int r = ROUNDS - 1; r > 0; r--) {
            i = r * 6;
            invSubkey[i + 4] = subkey[p++];         // 46 <- 4 ...
            invSubkey[i + 5] = subkey[p++];         // 47 <- 5 ...
            invSubkey[i]     = mulInv(subkey[p++]); // 42 <- 6 ...
            invSubkey[i + 2] = addInv(subkey[p++]); // 44 <- 7 ...
            invSubkey[i + 1] = addInv(subkey[p++]); // 43 <- 8 ...
            invSubkey[i + 3] = mulInv(subkey[p++]); // 45 <- 9 ...
        }
        // Runda 1
        invSubkey[4] = subkey[p++];                 // 4 <- 46
        invSubkey[5] = subkey[p++];                 // 5 <- 47
        invSubkey[0] = mulInv(subkey[p++]);         // 0 <- 48
        invSubkey[1] = addInv(subkey[p++]);         // 1 <- 49
        invSubkey[2] = addInv(subkey[p++]);         // 2 <- 50
        invSubkey[3] = mulInv(subkey[p]);           // 3 <- 51
        return invSubkey;
    }

    /**
     * Adaugare in grupul de adunat (mod 2^16).
     * Camp [0, 0xFFFF].
     */
    private static int add(int x, int y) {
        return (x + y) & 0xFFFF;
    }

    /**
     * Aditivul invers in grupul de aditivi (mod 2^16).
     * Camp [0, 0xFFFF].
     */
    private static int addInv(int x) {
        return (0x10000 - x) & 0xFFFF;
    }

    /**
     * Inmulțirea in grupul multiplicativ (mod 2^16+1 = mod 0x10001).
     * Camp [0, 0xFFFF].
     */
    private static int mul(int x, int y) {
        long m = (long) x * y;
        if (m != 0) {
            return (int) (m % 0x10001) & 0xFFFF;
        } else {
            if (x != 0 || y != 0) {
                return (1 - x - y) & 0xFFFF;
            }
            return 0;
        }
    }

    /** 
     * Inversare multiplicativă în grupul multiplicativ (mod 2^16+1 = mod 0x10001).
     * Utilizează algoritmul Extended Euclidean pentru a calcula inversul.
     * Pentru scopurile IDEA, sub-blocul cu totul zero este considerat a reprezenta 2^16 = −1
     * Pentru multiplicarea modulo 216 + 1; pentru multiplicare astfel inversul multiplicator al lui 0 este 0
     * Camp [0, 0xFFFF].
     */
    @SuppressWarnings("SuspiciousNameCombination")
    private static int mulInv(int x) {
        if (x <= 1) {
            // 0 si 1 sunt propriile inverse
            return x;
        }
        try {
            int y = 0x10001;
            int t0 = 1;
            int t1 = 0;
            while (true) {
                t1 += y / x * t0;
                y %= x;
                if (y == 1) {
                    return (1 - t1) & 0xffff;
                }
                t0 += x / y * t1;
                x %= y;
                if (x == 1) {
                    return t0;
                }
            }
        } catch (ArithmeticException e) {
            return 0;
        }
    }
}