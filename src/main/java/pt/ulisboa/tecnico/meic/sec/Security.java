package pt.ulisboa.tecnico.meic.sec;

import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidPasswordSignatureException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.HashMap;

class Security {

    private CryptoManager cryptoManager;
    private HashMap<String, Boolean> nounces;
    private KeyStore keyStore;

    Security(String keystorePath, char[] keystorePwd) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.cryptoManager = new CryptoManager();
        this.nounces = new HashMap<>();
        keyStore = CryptoUtilities.readKeystoreFile(keystorePath, keystorePwd);
    }

    String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(pubKey));
    }

    Password getPasswordReadyToSend(Password password) throws NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, KeyStoreException, InvalidKeyException {
        password.serverPublicKey = cryptoManager.convertBinaryToBase64(
                CryptoUtilities.getPublicKeyFromKeystore(keyStore, "asymm", "batata".toCharArray()).getEncoded());
        password.timestamp = String.valueOf(cryptoManager.getActualTimestamp().getTime());
        password.nonce = cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32));

        String[] fieldsToSend = new String[]{
                password.serverPublicKey,
                password.publicKey,
                password.domain,
                password.username,
                password.password,
                password.versionNumber,
                password.deviceId,
                password.pwdSignature,
                password.timestamp,
                password.nonce,
        };

        password.reqSignature = cryptoManager.convertBinaryToBase64(
                cryptoManager.signFields(fieldsToSend, keyStore, "asymm", "batata".toCharArray()));

        return password;
    }

    Password getPasswordReadyToSendToClient(Password password) throws NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, KeyStoreException, InvalidKeyException {
        password.publicKey = cryptoManager.convertBinaryToBase64(
                CryptoUtilities.getPublicKeyFromKeystore(keyStore, "asymm", "batata".toCharArray()).getEncoded());
        password.timestamp = String.valueOf(cryptoManager.getActualTimestamp().getTime());
        password.nonce = cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32));
        password.serverPublicKey = null;
        String[] fieldsToSend = new String[]{
                password.publicKey,
                password.domain,
                password.username,
                password.password,
                password.versionNumber,
                password.deviceId,
                password.pwdSignature,
                password.timestamp,
                password.nonce,
        };

        password.reqSignature = cryptoManager.convertBinaryToBase64(
                cryptoManager.signFields(fieldsToSend, keyStore, "asymm", "batata".toCharArray()));

        return password;
    }

    IV getIVReadyToSend(IV iv) throws NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, KeyStoreException, InvalidKeyException {
        iv.publicKey = cryptoManager.convertBinaryToBase64(
                CryptoUtilities.getPublicKeyFromKeystore(keyStore, "asymm", "batata".toCharArray()).getEncoded());
        iv.timestamp = String.valueOf(cryptoManager.getActualTimestamp().getTime());
        iv.nonce = cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32));

        String[] fieldsToSend = new String[]{
                iv.publicKey,
                iv.hash,
                iv.value,
                iv.timestamp,
                iv.nonce,
        };

        iv.reqSignature = cryptoManager.convertBinaryToBase64(
                cryptoManager.signFields(fieldsToSend, keyStore, "asymm", "batata".toCharArray()));

        return iv;
    }


    private void verifyFreshness(String nonce, String timestamp) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException {
        //Avoids replay attack
        if (!cryptoManager.isTimestampAndNonceValid(new Timestamp(Long.valueOf(timestamp)),
                cryptoManager.convertBase64ToBinary(nonce))) {
            throw new ExpiredTimestampException();
        }
    }

    void verifyPasswordInsertSignature(Password password) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidPasswordSignatureException, InvalidRequestSignatureException {
        String[] myFields;
        if (password.serverPublicKey == null) {
            myFields = new String[]{
                    password.publicKey,
                    password.domain,
                    password.username,
                    password.password,
                    password.versionNumber,
                    password.deviceId,
                    password.pwdSignature,
                    password.timestamp,
                    password.nonce
            };
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey)));
            if (!cryptoManager.isValidSig(publicKey, myFields, password.reqSignature))
                throw new InvalidRequestSignatureException();
        } else {
            myFields = new String[]{
                    password.serverPublicKey,
                    password.publicKey,
                    password.domain,
                    password.username,
                    password.password,
                    password.versionNumber,
                    password.deviceId,
                    password.pwdSignature,
                    password.timestamp,
                    password.nonce
            };
            PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.serverPublicKey)));
            if (!cryptoManager.isValidSig(serverPublicKey, myFields, password.reqSignature))
                throw new InvalidRequestSignatureException();
        }
        verifyFreshness(password.nonce, password.timestamp);
    }

    void verifyIVInsertSignature(IV iv) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidPasswordSignatureException, InvalidRequestSignatureException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(iv.publicKey))
        );

        String[] myFields = new String[]{
                iv.publicKey,
                iv.hash,
                iv.value,
                iv.timestamp,
                iv.nonce
        };

        if (!cryptoManager.isValidSig(publicKey, myFields, iv.reqSignature))
            throw new InvalidRequestSignatureException();
        verifyFreshness(iv.nonce, iv.timestamp);
    }

    void verifyPasswordFetchSignature(Password password) throws DuplicateRequestException, NoSuchAlgorithmException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidRequestSignatureException {

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey))
        );

        String[] myFields = new String[]{
                password.publicKey,
                password.domain,
                password.username,
                password.pwdSignature,
                password.timestamp,
                password.nonce
        };

        if (!cryptoManager.isValidSig(publicKey, myFields, password.reqSignature))
            throw new InvalidRequestSignatureException();
        verifyFreshness(password.nonce, password.timestamp);
    }

    void verifyIVFetchSignature(IV iv) throws DuplicateRequestException, NoSuchAlgorithmException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidRequestSignatureException {

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(iv.publicKey))
        );

        String[] myFields = new String[]{
                iv.publicKey,
                iv.hash,
                iv.timestamp,
                iv.nonce
        };

        if (!cryptoManager.isValidSig(publicKey, myFields, iv.reqSignature))
            throw new InvalidRequestSignatureException();
        verifyFreshness(iv.nonce, iv.timestamp);
    }

    void verifyPublicKeySignature(User user) throws ArrayIndexOutOfBoundsException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidRequestSignatureException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(user.publicKey)));
        if (!cryptoManager.isValidSig(publicKey, new String[]{user.publicKey}, user.signature))
            throw new InvalidRequestSignatureException();
    }
}
