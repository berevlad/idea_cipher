package com.tsd.idea_cipher.crypto;

/**
 * BlockCipher.
 */
public abstract class BlockCipher {

    private int keySize;
    private int blockSize;

    BlockCipher(int keySize, int blockSize) {
        this.keySize = keySize;
        this.blockSize = blockSize;
    }

    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Obtine cheia dintr-un bloc de octeti.
     */
    protected abstract void setKey(byte[] key);

    /**
     * Setare cheie dintr-un sir
     *
     * @param charKey sir cheie
     */
    protected void setKey(String charKey) {
        setKey(CrytoUtils.makeKey(charKey, keySize));
    }

    /**
     * Criptare / Decriptare bloc de 64-biti.
     *
     * @param data   64-biti bloc de date
     * @param offset punct de start
     */
    public abstract void crypt(byte[] data, int offset);

    /**
     * Criptare / Decriptare bloc de date de 64-biti.
     *
     * @param data 64-biti bloc de date
     */
    public void crypt(byte[] data) {
        crypt(data, 0);
    }
}
