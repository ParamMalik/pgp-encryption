package com.csvreader.csvtodatabase.encryptor;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

@Slf4j
@Component
public class PgpEncryptor {

    // public key for testing
    @Value("${pgp.public-key-file}")
    private String PUBLIC_KEY_FILE;


    public ByteArrayInputStream encryption(byte[] dataToEncrypt) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        // Load Public Key File
        var keysFile = new FileInputStream(PUBLIC_KEY_FILE);

        // Reading Public key
        var pubKey = readPublicKey(keysFile);

        // Encrypting the data
        return encryptFile(pubKey, dataToEncrypt);

    }

    private PGPPublicKey readPublicKey(InputStream publicKeyInputFile) throws IOException, PGPException {
        var localPGPPublicKeyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(publicKeyInputFile));
        var keyRing = localPGPPublicKeyRingCollection.getKeyRings();
        while (keyRing.hasNext()) {
            PGPPublicKeyRing localPGPPublicKeyRing = (PGPPublicKeyRing) keyRing.next();
            var publicKey = localPGPPublicKeyRing.getPublicKeys();
            while (publicKey.hasNext()) {
                var localPGPPublicKey = (PGPPublicKey) publicKey.next();
                if (localPGPPublicKey.isEncryptionKey())
                    return localPGPPublicKey;
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private ByteArrayInputStream encryptFile(PGPPublicKey encryptionPGPPublicKey, byte[] bytesToEncrypt)
            throws IOException, NoSuchProviderException {

        var byteArrayOutputStream = new ByteArrayOutputStream();
        OutputStream outputStream = byteArrayOutputStream;
        OutputStream openStream = null;

        outputStream = new ArmoredOutputStream(outputStream);
        var arrayOfByte = compress(bytesToEncrypt);
        var encryptedDataGenerator = new PGPEncryptedDataGenerator(SymmetricKeyAlgorithmTags.AES_256, true, new SecureRandom(), "BC");

        try {
            encryptedDataGenerator.addMethod(encryptionPGPPublicKey);
            openStream = encryptedDataGenerator.open(outputStream, arrayOfByte.length);
            openStream.write(arrayOfByte);

        } catch (PGPException localPGPException) {
            log.error("PGP Error occurred:{}",localPGPException.getMessage());
            return null;

        } finally {
            assert openStream != null;
            openStream.close();
            outputStream.close();
        }

        var encryptedDataAsString = byteArrayOutputStream.toString();

        return new ByteArrayInputStream(encryptedDataAsString.getBytes());
    }


    // Compressing
    private static byte[] compress(byte[] byteDataToEncrypt) throws IOException {

        var byteArrayOutputStream = new ByteArrayOutputStream();
        var compressedData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        var compressedOutputStream = compressedData.open(byteArrayOutputStream);
        var localPGPCompressedDataGenerator = new PGPLiteralDataGenerator();
        var outputStream = localPGPCompressedDataGenerator.open(compressedOutputStream, // the compressed output stream
                PGPLiteralData.BINARY,
                "",
                byteDataToEncrypt.length,
                new Date()
        );

        outputStream.write(byteDataToEncrypt);

        outputStream.close();
        compressedData.close();

        return byteArrayOutputStream.toByteArray();
    }

}

