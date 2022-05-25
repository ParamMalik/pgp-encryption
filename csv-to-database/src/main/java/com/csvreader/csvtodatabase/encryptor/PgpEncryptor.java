package com.csvreader.csvtodatabase.encryptor;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

@Component
public class PgpEncryptor {

    public void encryption(byte[] dataToEncrypt, String publicKeyFilePath) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        // Load Public Key File
        var keysFile = new FileInputStream(publicKeyFilePath);

        // Reading Public key
        var pubKey = readPublicKey(keysFile);

        // Encrypting the data
        encryptFile(pubKey, dataToEncrypt);

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

    private void encryptFile(PGPPublicKey encryptionPGPPublicKey, byte[] bytesToEncrypt)
            throws IOException, NoSuchProviderException {

        var byteArrayOutputStream = new ByteArrayOutputStream();

        OutputStream outputStream = byteArrayOutputStream;

        var integrityCheck = true;

        outputStream = new ArmoredOutputStream(outputStream);
        try {

            var arrayOfByte = compress(bytesToEncrypt);


            var encryptedDataGenerator = new PGPEncryptedDataGenerator(SymmetricKeyAlgorithmTags.AES_256, integrityCheck, new SecureRandom(), "BC");
            encryptedDataGenerator.addMethod(encryptionPGPPublicKey);

            var openStream = encryptedDataGenerator.open(outputStream, arrayOfByte.length);
            openStream.write(arrayOfByte);

            openStream.close();
            outputStream.close();

            var encryptedDataAsString = byteArrayOutputStream.toString();

            System.out.println(encryptedDataAsString);

        } catch (PGPException localPGPException) {
            System.err.println("Local PGP Error occurred");
            if (localPGPException.getUnderlyingException() != null)
                localPGPException.getUnderlyingException().printStackTrace();
        }
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

