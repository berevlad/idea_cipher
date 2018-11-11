package com.tsd.idea_cipher.modes.algorithms;

import com.tsd.idea_cipher.crypto.CrytoUtils;
import com.tsd.idea_cipher.crypto.IdeaCipher;
import com.tsd.idea_cipher.modes.OperationMode;

import java.util.Arrays;

/**
 * CFB 
 * r = 8 octeti
 */
public class CFB extends OperationMode {

    private static final int R = 8;

    private int blockSize;
    private int partSize;
    private int rounds;
    private byte[] feedback;

    public CFB(boolean encrypt, String key) {
        super(new IdeaCipher(key, true), encrypt);
        blockSize = idea.getBlockSize();
        assert blockSize % R == 0 : "R must be divisor of blockSize";
        partSize = R;
        rounds = blockSize / R;
        feedback = CrytoUtils.makeKey(key, blockSize); // Obtine vectorul intitial (IV) din cheia utilizatoruui
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        // Imparte blocul de date cu dimensiunea blockSize la blocurile partSize
        byte[][] block = new byte[rounds][];
        for (int i = 0; i < rounds; i++) {
            block[i] = Arrays.copyOfRange(data, pos + partSize * i, pos + partSize * i + partSize);
        }
        // -> save criptograma (necesara in operatia xor)
        byte[][] crypt = new byte[0][];
        if (!this.isEncrypt()) {
            crypt = new byte[rounds][];
            for (int i = 0; i < rounds; i++) {
                crypt[i] = block[i].clone();
            }
        }
        // Porneste algoritmul CFB
        byte[] feedbackP1, feedbackP2;
        for (int i = 0; i < rounds; i++) {
            idea.crypt(feedback);                                           // Cripteaza feedback
            feedbackP1 = Arrays.copyOfRange(feedback, 0, partSize);         // Cel mai din stanga R-Bytes al feedback-ului
            feedbackP2 = Arrays.copyOfRange(feedback, partSize, blockSize); // Cel mai din dreapta (blockSize-R)-Bytes al feedback-ului
            CrytoUtils.xor(block[i], 0, feedbackP1, partSize);              // XOR parte din date si feedback
            if (this.isEncrypt()) {
                feedback = CrytoUtils.concat2Bytes(feedbackP2, block[i]);   // Actualizeaza feedback cu noul bloc de cifre
            } else {
                feedback = CrytoUtils.concat2Bytes(feedbackP2, crypt[i]);   // Actualizeaza feedback cu noul bloc de cifre salvate
            }
        }
        // Unirea rezultatelor
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(block[i], 0, data, pos + partSize * i, partSize);
        }
    }
}