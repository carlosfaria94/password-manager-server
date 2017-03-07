package pt.ulisboa.tecnico.meic.sec;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class Security {

    private CryptoManager cryptoManager = new CryptoManager();

    public String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        return cryptoManager.convertBinaryToBase64(cryptoManager.digest(pubKey));
    }
}
