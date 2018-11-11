package com.tsd.idea_cipher.modes.algorithms;

import com.tsd.idea_cipher.crypto.IdeaCipher;
import com.tsd.idea_cipher.modes.OperationMode;


/**
 * ECB 
 * Mesaju e impartit pe blocuri, si fiecare bloc e criptat separat.
 */
public class ECB extends OperationMode {

    public ECB(boolean encrypt, String key) {
        super(new IdeaCipher(key, encrypt), encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(data, pos); // Criptare / decriptare bloc
    }
}
