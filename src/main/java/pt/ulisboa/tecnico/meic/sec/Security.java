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
        password.publicKey = cryptoManager.convertBinaryToBase64(
                CryptoUtilities.getPublicKeyFromKeystore(keyStore, "asymm", "batata".toCharArray()).getEncoded());
        password.timestamp = cryptoManager.getActualTimestamp().toString();
        password.nonce = cryptoManager.convertBinaryToBase64(cryptoManager.generateNonce(32));

        String[] fieldsToSend = new String[]{
                password.publicKey,
                password.domain, // domain
                password.username, // username
                password.password, // password
                password.pwdSignature,
                password.timestamp,
                password.nonce,
        };

        password.reqSignature = cryptoManager.convertBinaryToBase64(
                cryptoManager.signFields(fieldsToSend, keyStore, "asymm", "batata".toCharArray()));

        return password;
    }


    private void verifyRequest(String nonce, String timestamp, String publicKey) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException {
        //TODO FIXME XXX Erro semântico??
        //Avoids replay attack
        if(!cryptoManager.isTimestampAndNonceValid(java.sql.Timestamp.valueOf(timestamp),
            cryptoManager.convertBase64ToBinary(nonce))){
            throw new ExpiredTimestampException();
        }
    }

    void verifyPasswordInsertSignature(Password password) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidPasswordSignatureException, InvalidRequestSignatureException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey)));

        String[] myFields = new String[]{password.publicKey,
                password.domain,
                password.username,
                password.password,
                password.pwdSignature,
                password.timestamp,
                password.nonce};

        cryptoManager.isValidSig(publicKey, myFields, password.reqSignature);
        verifyRequest(password.nonce, password.timestamp, password.publicKey);
    }

    void verifyPasswordFetchSignature(Password password) throws DuplicateRequestException, NoSuchAlgorithmException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException {

        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey)));


        String[] myFields = new String[]{password.publicKey,
                password.domain,
                password.username,
                password.timestamp,
                password.nonce};

        cryptoManager.isValidSig(publicKey, myFields, password.reqSignature);
        verifyRequest(password.nonce, password.timestamp, password.publicKey);
    }

    void verifyPublicKeySignature(User user) throws ArrayIndexOutOfBoundsException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(user.publicKey)));
        cryptoManager.isValidSig(publicKey, new String[]{user.publicKey}, user.signature);
    }
}
