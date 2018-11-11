package com.tsd.idea_cipher.modes;

import com.tsd.idea_cipher.modes.algorithms.CBC;
import com.tsd.idea_cipher.modes.algorithms.CFB;
import com.tsd.idea_cipher.modes.algorithms.ECB;
import com.tsd.idea_cipher.modes.algorithms.OFB;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * Encripteaza sau decripteaza un fisier cu diferite moduri de operare.
 *
 * Bazat pe urmatorul link: http://www.source-code.biz/idea/java
 */
public class FileCipher extends Task<Void> {

    private static final Logger logger = LoggerFactory.getLogger(FileCipher.class);
    private static final int BLOCK_SIZE = 8;

    private String input;
    private String output;
    private String key;
    private boolean encrypt;
    private OperationMode.Mode mode;
    private StringProperty status; // Pentru a afisa mesaje in box-ul de stare

    public FileCipher(String input, String output, String key, boolean encrypt, OperationMode.Mode mode) {
        this.input = input;
        this.output = output;
        this.key = key;
        this.encrypt = encrypt;
        this.mode = mode;
        status = new SimpleStringProperty();
    }

    public StringProperty getStatus() {
        return status;
    }

    /**
     * Criptare/ decriptare fisiere.
     */
    private void cryptFile() throws IOException {
        // Deschide input / output FileChannels
        try (FileChannel inChannel = FileChannel.open(Paths.get(input), StandardOpenOption.READ);
             FileChannel outChannel = FileChannel.open(Paths.get(output), StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {

            // Selectarea modului de operare
            OperationMode opMod;
            switch (mode) {
                case ECB:
                    opMod = new ECB(encrypt, key);
                    break;
                case CBC:
                    opMod = new CBC(encrypt, key);
                    break;
                case CFB:
                    opMod = new CFB(encrypt, key);
                    break;
                case OFB:
                    opMod = new OFB(key);
                    break;
                default:
                    throw new IllegalArgumentException("Incorrect mode of operation.");
            }
            logger.debug(encrypt ? "Encrypting..." : "Decrypting...");
            logger.debug("Mode: " + mode.toString());
            status.setValue((encrypt ? "Encrypting" : "Decrypting") + " file with " + mode.toString() + " mode.");

            // Verifica si calculeaza dimensiunea datelor
            long inFileSize = inChannel.size(); // Dimensiunea fisierului de intrare (bytes)
            long inDataLen, outDataLen; // Dimensiunea datelor de intrare/ iesire (bytes)
            if (encrypt) {
                inDataLen = inFileSize; // Dimensiunea datelor de intrare = Dimensiunea fisierului de intrare
                outDataLen = (inDataLen + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; 
                logger.debug("Sizes: " + inDataLen + "b input, " + (outDataLen + BLOCK_SIZE) + "b output");
                status.setValue("Input size: " + inDataLen / 1024 + "KB.");
            } else {
                if (inFileSize == 0) {
                    throw new IOException("Input file is empty.");
                } else if (inFileSize % BLOCK_SIZE != 0) {
                    throw new IOException("Input file size is not a multiple of " + BLOCK_SIZE + ".");
                }
                inDataLen = inFileSize - BLOCK_SIZE; // Ultimul bloc e dimensiunea datelor (criptat)
                outDataLen = inDataLen;
                logger.debug("Sizes: " + (inDataLen + BLOCK_SIZE) + "b input, <=" + outDataLen  + "b output");
                status.setValue("Input size: " + (inDataLen + BLOCK_SIZE) / 1024 + "KB.");
            }

            // Criptare / Decriptare date
            status.setValue("Running IDEA...");
            long t0 = System.currentTimeMillis();
            processData(inChannel, inDataLen, outChannel, outDataLen, opMod);
            long tf = (System.currentTimeMillis() - t0);
            status.setValue((encrypt ? "Encryption" : "Decryption") + " finished (" + tf + "ms).");

            // Scrie / citire lungimea datelor
            if (encrypt) {
                status.setValue("Attaching file size encrypted...");
                // Adauga lungimea datelor criptate intr-un bloc criptat la sfarsitul fisierului de iesire.
                writeDataLength(outChannel, inDataLen, opMod);
                status.setValue("Output size: " + inDataLen / 1024 + "KB.");
            } else {
                status.setValue("Checking file size...");
                // Citeste dimensiunea fisierului
                long dataSize = readDataLength(inChannel, opMod);
                // Verifica daca e un fisier valid
                if (dataSize < 0 || dataSize > inDataLen || dataSize < inDataLen - BLOCK_SIZE + 1) {
                    throw new IOException("Input file is not a valid cryptogram (wrong file size)");
                }
                // Trunchiaza fisierul de iesire la valoarea datelor
                if (dataSize != outDataLen) {
                    outChannel.truncate(dataSize);
                    status.setValue("Truncating output file...");
                    logger.debug("Truncate " + outDataLen + "b to " + dataSize + "b");
                }
                status.setValue("Output size: " + dataSize / 1024 + "KB.");
            }
            status.setValue("Done!");
        }
    }

    /**
     * Citeste fisierul de intrare in parti de cate 2 MB, cripteaza / decripteaza o parte si scrie in fisierul de iesire.
     */
    private void processData(FileChannel inChannel, long inDataLen, FileChannel outChannel, long outDataLen,
                                    OperationMode opMod) throws IOException {
        final int bufSize = 0x200000; // 2MB de buffer
        ByteBuffer buf = ByteBuffer.allocate(bufSize);
        long filePos = 0;
        while (filePos < inDataLen) {
            // Setare progres
            updateProgress(filePos, inDataLen);
            // Citeste din fisierul de intrare in buffer
            int bytesToRead = (int) Math.min(inDataLen - filePos, bufSize);
            buf.limit(bytesToRead);
            buf.position(0);
            int bytesRead = inChannel.read(buf);
            if (bytesRead != bytesToRead) {
                throw new IOException("Incomplete data chunk read from file.");
            }
            // Cripteaza partea (bucata)
            int chunkLen = (bytesRead + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; // Cea mai apropiata celula superioara a blockSize-ului
            Arrays.fill(buf.array(), bytesRead, chunkLen, (byte) 0); // Umple spatiul liber al bucatii cu 0
            for (int pos = 0; pos < chunkLen; pos += BLOCK_SIZE) {
                opMod.crypt(buf.array(), pos); // Cripteaza partea respectiva cu modul de operare ales.
            }
            // Scrie buffer la fisierul de iesire
            int bytesToWrite = (int) Math.min(outDataLen - filePos, chunkLen);
            buf.limit(bytesToWrite);
            buf.position(0);
            int bytesWritten = outChannel.write(buf);
            if (bytesWritten != bytesToWrite) {
                throw new IOException("Incomplete data chunk written to file.");
            }
            filePos += chunkLen;
        }
    }

    /**
     * Scrie lungimea datelor criptate intr-un bloc criptat la sfarsitul fisierului.
     * Lungimea este un pachet de 8 octeti, acest bloc e criptat, iar la finalul e adaugat la sfarsitul fisierului de iesire
     */
    private void writeDataLength(FileChannel outChannel, long dataLength, OperationMode opMod)
            throws IOException {
        // Impachetare dataLength intr-un bloc de 8 octeti
        byte[] block = packDataLength(dataLength);
        // Encrypt block
        opMod.crypt(block);
        // Scrie blocul la finalul fisierului.
        ByteBuffer buf = ByteBuffer.wrap(block);
        int bytesWritten = outChannel.write(buf);
        if (bytesWritten != BLOCK_SIZE) {
            throw new IOException("Error while writing data length suffix.");
        }
    }

    /**
     * Obtine lungimea datelor ce  au fost criptate
     * Aceste date sunt salvate criptate in ultimul bloc al criptogramei 
     * Read the last block of the file, decrypt block and unpackage data lenght.
     */
    private long readDataLength(FileChannel channel, OperationMode opMod) throws IOException {
        // Obtine ultimul bloc
        ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE);
        int bytesRead = channel.read(buf);
        if (bytesRead != BLOCK_SIZE) {
            throw new IOException("Unable to read data length suffix.");
        }
        byte[] block = buf.array();
        // Decriptare bloc
        opMod.crypt(block);
        // Despachetare lungimea datelor
        return unpackDataLength(block);
    }

    /**
     * Impacheteaza un numar de 45 de biti in blocuri de 8 octeti
     */
    private static byte[] packDataLength(long size) {
        if (size > 0x1FFFFFFFFFFFL) { // 45 bits -> 32TB
            throw new IllegalArgumentException("File too long.");
        }
        byte[] b = new byte[BLOCK_SIZE];
        b[7] = (byte) (size << 3);
        b[6] = (byte) (size >> 5);
        b[5] = (byte) (size >> 13);
        b[4] = (byte) (size >> 21);
        b[3] = (byte) (size >> 29);
        b[2] = (byte) (size >> 37);
        return b;
    }

    /**
     * Folosit sa decripteze dimensiunea fisierului.
     * Returneaza -1 daca valoarea encodata e invalida.
     */
    private static long unpackDataLength(byte[] b) {
        if (b[0] != 0 || b[1] != 0 || (b[7] & 7) != 0) {
            return -1;
        }
        return (long) (b[7] & 0xFF) >> 3 |
                (long) (b[6] & 0xFF) << 5 |
                (long) (b[5] & 0xFF) << 13 |
                (long) (b[4] & 0xFF) << 21 |
                (long) (b[3] & 0xFF) << 29 |
                (long) (b[2] & 0xFF) << 37;
    }

    @Override
    protected Void call() throws Exception {
        updateProgress(0, 1);
        cryptFile();
        updateProgress(1, 1);
        return null;
    }
}
