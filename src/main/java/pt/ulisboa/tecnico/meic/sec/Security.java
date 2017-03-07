package pt.ulisboa.tecnico.meic.sec;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class Security {

    private CryptoManager cryptoManager = new CryptoManager();

    public String generateFingerprint(String publicKey) throws NoSuchAlgorithmException {
        System.out.println(publicKey);
        byte[] pubKey = publicKey.getBytes(StandardCharsets.UTF_8);
        byte[] fingerprint = cryptoManager.digest(pubKey);
        System.out.println(fingerprint);
        return new String(fingerprint, StandardCharsets.UTF_8);
    }
}
