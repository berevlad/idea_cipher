package com.tsd.idea_cipher.modes.algorithms;

import com.tsd.idea_cipher.crypto.CrytoUtils;
import com.tsd.idea_cipher.crypto.IdeaCipher;
import com.tsd.idea_cipher.modes.OperationMode;

/**
 * OFB
 * Genereaza blocuri de chei care apoi folosesc XOR impreuna cu blocurile de text pentru a obtine cheia textului.
 */
public class OFB extends OperationMode {

    private int blockSize;
    private byte[] feedback;

    public OFB(String key) {
        super(new IdeaCipher(key, true), true);
        blockSize = idea.getBlockSize();
        feedback = CrytoUtils.makeKey(key, blockSize); // Obtine vectorul initial (IV) din cheia utilizatorului
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(feedback);                           // Criptare feedback
        CrytoUtils.xor(data, pos, feedback, blockSize); // XOR pe date si feecback
    }
}