package pt.ulisboa.tecnico.meic.sec;

import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;

class Security {

    private CryptoManager cryptoManager;
    private KeyStore keyStore;

    Security(String keystorePath, char[] keystorePwd) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.cryptoManager = new CryptoManager();
        keyStore = CryptoUtilities.readKeystoreFile(keystorePath, keystorePwd);
    }

    String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(pubKey));
    }

    SecureEntity getEntityReadyToSend(SecureEntity entity)
            throws NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, KeyStoreException,
            InvalidKeyException {
        entity.publicKey = cryptoManager.convertBinaryToBase64(
                CryptoUtilities.getPublicKeyFromKeystore(keyStore, "asymm", "batata".toCharArray()).getEncoded());
        entity.timestamp = String.valueOf(cryptoManager.getActualTimestamp().getTime());
        entity.nonce = cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32));

        String[] fieldsToSend = entity.getFieldsReadyToSend();

        entity.reqSignature = cryptoManager.convertBinaryToBase64(
                cryptoManager.signFields(fieldsToSend, keyStore, "asymm", "batata".toCharArray()));

        return entity;
    }

    void verifyInsertSignature(SecureEntity entity)
            throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            InvalidRequestSignatureException, ExpiredTimestampException, DuplicateRequestException {
        PublicKey publicKey = getPublicKeyFromBase64(entity.publicKey);
        String[] myFields = entity.getInsertFields();

        if (!cryptoManager.isValidSig(publicKey, myFields, entity.reqSignature))
            throw new InvalidRequestSignatureException();
        verifyFreshness(entity.nonce, entity.timestamp);
    }

    void verifyFetchSignature(SecureEntity entity)
            throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            InvalidRequestSignatureException, ExpiredTimestampException, DuplicateRequestException {
        PublicKey publicKey = getPublicKeyFromBase64(entity.publicKey);
        String[] myFields = entity.getRetrieveFields();

        if (!cryptoManager.isValidSig(publicKey, myFields, entity.reqSignature))
            throw new InvalidRequestSignatureException();
        verifyFreshness(entity.nonce, entity.timestamp);
    }


    void verifyFreshness(String nonce, String timestamp) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException {
        //Avoids replay attack
        if (!cryptoManager.isTimestampAndNonceValid(new Timestamp(Long.valueOf(timestamp)),
                cryptoManager.convertBase64ToBinary(nonce))) {
            throw new ExpiredTimestampException();
        }
    }

    void verifyPublicKeySignature(User user) throws ArrayIndexOutOfBoundsException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidRequestSignatureException {
        PublicKey publicKey = getPublicKeyFromBase64(user.publicKey);

        if (!cryptoManager.isValidSig(publicKey, new String[]{user.publicKey}, user.signature))
            throw new InvalidRequestSignatureException();
    }

    private PublicKey getPublicKeyFromBase64(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(
                cryptoManager.convertBase64ToBinary(key)));
    }
}
