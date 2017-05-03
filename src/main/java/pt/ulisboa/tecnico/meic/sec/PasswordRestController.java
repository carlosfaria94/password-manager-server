package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidPasswordSignatureException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.util.ArrayList;

@RestController
class PasswordRestController {
    private final PasswordRepository passwordRepository;
    private final UserRepository userRepository;
    private Security sec;

    @Autowired
    PasswordRestController(PasswordRepository passwordRepository,
                           UserRepository userRepository) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;

        String serverName = System.getenv("SERVER_NAME");
        String keystorePath = "keystore-" + serverName + ".jceks";
        String keystorePwd = "batata";

        sec = new Security(keystorePath, keystorePwd.toCharArray());
    }

    @RequestMapping(value = "/retrievePassword", method = RequestMethod.POST)
    ResponseEntity<?> retrievePassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, InvalidPasswordSignatureException, ExpiredTimestampException, DuplicateRequestException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyFetchSignature(input);

        ArrayList<Password> passwords = new ArrayList<>(this.passwordRepository.findByUserFingerprintAndDomainAndUsername(
                fingerprint,
                input.domain,
                input.username
        ));

        if (passwords.isEmpty()) {
            return new ResponseEntity<>(null, null, HttpStatus.NOT_FOUND);
        } else {
            Password maximum = passwords.get(0);
            for (Password p : passwords) {
                if(Timestamp.valueOf(p.timestamp).getTime() >
                        Timestamp.valueOf(maximum.timestamp).getTime()) {
                    maximum = p;
                }
            }
            Password p = (Password) sec.getEntityReadyToSend(maximum);
            return new ResponseEntity<>(p, null, HttpStatus.OK);
        }
    }


    @RequestMapping(value = "/password", method = RequestMethod.PUT)
    ResponseEntity<?> addPassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, ExpiredTimestampException, DuplicateRequestException, InvalidPasswordSignatureException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyInsertSignature(input);

        System.out.println(input);

        return this.userRepository.findByFingerprint(fingerprint).map((User user) -> {

            Password newPwd = passwordRepository.save(new Password(
                    user,
                    input.domain,
                    input.username,
                    input.password,
                    input.versionNumber,
                    input.deviceId,
                    input.iv,
                    input.pwdSignature,
                    input.timestamp,
                    input.nonce,
                    input.reqSignature
            ));

            System.out.println("New password registered. ID: " + newPwd.getId());

            Password p = null;
            try {
                p = (Password) sec.getEntityReadyToSend(newPwd);
            } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | InvalidKeyException |
                    SignatureException | NullPointerException e) {
                e.printStackTrace();
            }

            return new ResponseEntity<>(p, null, HttpStatus.CREATED);
        }).orElse(ResponseEntity.noContent().build());
    }

    /**
     * Only verify if user is already registered
     *
     * @param publicKey
     * @return fingerprint
     * @throws NoSuchAlgorithmException
     */
    private String validateUser(String publicKey) throws NoSuchAlgorithmException {
        String fingerprint = sec.generateFingerprint(publicKey);
        this.userRepository.findByFingerprint(fingerprint).orElseThrow(
                () -> new UserNotFoundException());
        return fingerprint;
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Request is not correctly signed")
    @ExceptionHandler({InvalidRequestSignatureException.class})
    public void invalidRequestSignatureException() {
        System.err.println("Request is not correctly signed.");
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Password is not correctly signed")
    @ExceptionHandler({InvalidPasswordSignatureException.class})
    public void invalidPasswordSignatureException() {
        System.err.println("Password is not correctly signed.");
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Request expired")
    @ExceptionHandler({ExpiredTimestampException.class})
    public void expiredTimestampException() {
        System.err.println("Request expired.");
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Request already received")
    @ExceptionHandler({DuplicateRequestException.class})
    public void duplicateRequestException() {
        System.err.println("Request already received");
    }

    @ResponseStatus(value= HttpStatus.BAD_REQUEST, reason="Something is missing.")
    @ExceptionHandler({NullPointerException.class})
    public void nullException() {
        System.err.println("Something is missing.");
    }

    @ResponseStatus(value= HttpStatus.BAD_REQUEST, reason="Cryptographic algorithm is not available.")
    @ExceptionHandler({NoSuchAlgorithmException.class})
    public void noAlgorithm() {
        System.err.println("Cryptographic algorithm is not available.");
    }
}