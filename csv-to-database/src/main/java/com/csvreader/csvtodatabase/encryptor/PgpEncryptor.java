package com.csvreader.csvtodatabase.encryptor;

import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class PgpEncryptor {
    public void encryption(byte[] dataToEncrypt, String publicKeyFilePath) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        // Load Public Key File
        FileInputStream keysFile = new FileInputStream(publicKeyFilePath);
        PGPPublicKey pubKey = readPublicKey(keysFile);

        encryptFile(pubKey, dataToEncrypt);


    }

    private PGPPublicKey readPublicKey(InputStream paramInputStream) throws IOException, PGPException {
        PGPPublicKeyRingCollection localPGPPublicKeyRingCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(paramInputStream));
        Iterator keyRing = localPGPPublicKeyRingCollection.getKeyRings();
        while (keyRing.hasNext()) {
            PGPPublicKeyRing localPGPPublicKeyRing = (PGPPublicKeyRing) keyRing.next();
            Iterator publicKey = localPGPPublicKeyRing.getPublicKeys();
            while (publicKey.hasNext()) {
                PGPPublicKey localPGPPublicKey = (PGPPublicKey) publicKey.next();
                if (localPGPPublicKey.isEncryptionKey())
                    return localPGPPublicKey;
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private void encryptFile(PGPPublicKey encryptionPGPPublicKey, byte[] bytesToEncrypt)
            throws IOException, NoSuchProviderException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        OutputStream outputStream = byteArrayOutputStream;

        var integrityCheck = true;

        outputStream = new ArmoredOutputStream(outputStream);
        try {

            byte[] arrayOfByte = compress(bytesToEncrypt);


            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(SymmetricKeyAlgorithmTags.AES_256, integrityCheck, new SecureRandom(), "BC");
            encryptedDataGenerator.addMethod(encryptionPGPPublicKey);

            OutputStream openStream = encryptedDataGenerator.open(outputStream, arrayOfByte.length);
            openStream.write(arrayOfByte);

            openStream.close();
            outputStream.close();

            String s = byteArrayOutputStream.toString();

            System.out.println(s);

        } catch (PGPException localPGPException) {
            System.err.println("Local PGP Error occurred");
            if (localPGPException.getUnderlyingException() != null)
                localPGPException.getUnderlyingException().printStackTrace();
        }
    }


    // Compressing
    private static byte[] compress(byte[] byteDataToEncrypt) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        PGPCompressedDataGenerator compressedData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);

        OutputStream compressedOutputStream = compressedData.open(byteArrayOutputStream); // open it with the final destination

        PGPLiteralDataGenerator localPGPCompressedDataGenerator = new PGPLiteralDataGenerator();

        OutputStream outputStream = localPGPCompressedDataGenerator.open(compressedOutputStream, // the compressed output stream
                PGPLiteralData.BINARY,
                "",  // "filename" to store
                byteDataToEncrypt.length, // length of clear data
                new Date()  // current time
        );

        outputStream.write(byteDataToEncrypt);
        outputStream.close();

        compressedData.close();

        return byteArrayOutputStream.toByteArray();
    }

}

