package pt.ulisboa.tecnico.meic.sec;

import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidPasswordSignatureException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.HashMap;

public class Security {

    private CryptoManager cryptoManager = new CryptoManager();
    private HashMap<String, Boolean> nounces = new HashMap<>();

    public String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(pubKey));
    }

    private void verifyRequest(String nonce, Instant timestamp, String publicKey) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException {
        //TODO FIXME XXX Erro semântico??
        //Avoids replay attack
        if(Instant.now().isAfter(timestamp.plusSeconds(30))){
            throw new ExpiredTimestampException();
        }

        //Avoids replay attack
        String n = nonce + generateFingerprint(publicKey);
        if(nounces.containsKey(n)){
            throw new DuplicateRequestException();
        }

        nounces.put(n, true);
    }

    public void verifyPasswordSignature(Password password) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException, InvalidKeySpecException, SignatureException, InvalidKeyException, InvalidPasswordSignatureException, InvalidRequestSignatureException {
        verifyRequest(password.nonce, password.timestamp, password.publicKey);

        //Verificar assinaturas dos campos em base64 ou bytes??
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cryptoManager.convertBase64ToBinary(password.publicKey)));
        String passwordEntry = password.domain + password.username + password.password;
        String request = password.pwdSignature + password.timestamp + password.nonce;

        if(!cryptoManager.verifyDigitalSignature(password.reqSignature.getBytes(), request.getBytes(), publicKey)){
            throw new InvalidRequestSignatureException();
        }

        if(!cryptoManager.verifyDigitalSignature(password.pwdSignature.getBytes(), passwordEntry.getBytes(), publicKey)){
            throw new InvalidPasswordSignatureException();
        }
    }
}
