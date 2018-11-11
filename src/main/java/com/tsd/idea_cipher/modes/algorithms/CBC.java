package com.tsd.idea_cipher.modes.algorithms;

import com.tsd.idea_cipher.crypto.CrytoUtils;
import com.tsd.idea_cipher.crypto.IdeaCipher;
import com.tsd.idea_cipher.modes.OperationMode;

/**
 * CBC
 * Pe fiecare bloc de text este folosita functia XOR cu blocul precedent de cifru, inainte de a fi criptat
 * In acest mod, fiecare bloc de cod cifrat depinde de toate blocurile de texte procesate pana la acel punct.
 * Pentru a face fiecare mesaj unic, e folosit un vector initial generat de cheia utilizatorului.
 */ 
public class CBC extends OperationMode {

    private int blockSize;
    private byte[] prev;
    private byte[] newPrev;

    public CBC(boolean encrypt, String key) {
        super(new IdeaCipher(key, encrypt), encrypt);
        blockSize = idea.getBlockSize();
        prev = CrytoUtils.makeKey(key, blockSize); // Obtine vectorul initial (IV) din cheia utilizatorului
        newPrev = new byte[blockSize];
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        if (encrypt) {
            CrytoUtils.xor(data, pos, prev, blockSize);         // Bloc XOR cu un bloc criptat anterior
            idea.crypt(data, pos);                              // Cripteaza bloc
            System.arraycopy(data, pos, prev, 0, blockSize);    // Salveaza blocul criptat pentru data urmatoare
        } else {
            System.arraycopy(data, pos, newPrev, 0, blockSize); // Salveaza blocul criptat pentru data urmatoare.
            idea.crypt(data, pos);                              // Decripteaza bloc
            CrytoUtils.xor(data, pos, prev, blockSize);         // Bloc XOR cu un bloc criptat anterior
            prev = newPrev.clone();                             // Actualizare bloc anterior
        }
    }
}
