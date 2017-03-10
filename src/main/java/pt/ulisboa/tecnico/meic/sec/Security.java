package pt.ulisboa.tecnico.meic.sec;

import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
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

    public void verifyPasswordSignature(Password password) throws NoSuchAlgorithmException, DuplicateRequestException, ExpiredTimestampException {
        verifyRequest(password.nonce, password.timestamp, password.publicKey);

        //FIXME verificar as assinaturas
    }
}
