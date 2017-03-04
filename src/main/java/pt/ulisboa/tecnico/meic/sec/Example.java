package pt.ulisboa.tecnico.meic.sec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import java.io.FileNotFoundException;
import java.security.*;
import java.io.FileInputStream;
import java.time.Instant;

public class Example {
    private static byte[] sign(PrivateKey key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verifySignature(PublicKey key, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(signature);
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static String generateNonce(){
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);

        return Instant.now().toString()+"|"+printHexBinary(bytes);
    }

	public static void main(String[] args) {
        FileInputStream is = null;
		try{
            is = new FileInputStream("res\\server.jks");
        }
        catch (FileNotFoundException e){
		    System.err.println("Jks not found");
		    System.exit(1);
        }

        String jks_alias = "key";
        String jks_password = "batata123";

        String domain = "fenix.tecnico.ulisboa.pt";
        String username = "ist123456";
        String password = "batatinha12345";

        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, jks_password.toCharArray());

            final PrivateKey privateKey = (PrivateKey) keystore.getKey(jks_alias, jks_password.toCharArray());
            final PublicKey publicKey = keystore.getCertificate(jks_alias).getPublicKey();
            final SecretKey AESKey = generateAESKey();

            Cipher AesCipher = Cipher.getInstance("AES");
            AesCipher.init(Cipher.ENCRYPT_MODE, AESKey);

            //Encriptar com AES
            byte[] cipherPassword = AesCipher.doFinal(password.getBytes());

            //Assinar encriptação
            byte[] bytesSigned = sign(privateKey, cipherPassword);
            System.out.println("Singature: " + printHexBinary(bytesSigned));

            //bytesSigned[0] = 0x0;

            //Verificar assinatura da password encriptada
            System.out.println("Is valid signature? " + (verifySignature(publicKey, cipherPassword, bytesSigned)?"Yes":"No"));

            //Desencriptar assinatura
            AesCipher.init(Cipher.DECRYPT_MODE, AESKey);
            byte[] passwordBytes = AesCipher.doFinal(cipherPassword);
            System.out.println("Original password: " + new String(passwordBytes));

            //Gerar um nonce
            System.out.println("Nonce: " + generateNonce());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
	