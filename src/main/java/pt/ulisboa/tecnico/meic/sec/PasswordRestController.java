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
import java.util.ArrayList;

@RestController
class PasswordRestController {

    private final PasswordRepository passwordRepository;

    private final UserRepository userRepository;
    private final String keystorePath;
    private final String keystorePwd;
    private final String serverName = System.getenv("SERVER_NAME");
    private ServerCallsPool call;

    private Security sec;

    @Autowired
    PasswordRestController(PasswordRepository passwordRepository,
                           UserRepository userRepository) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
        keystorePath = "keystore-" + serverName + ".jceks";
        keystorePwd = "batata";
        sec = new Security(keystorePath, keystorePwd.toCharArray());
        call = new ServerCallsPool();
    }

    @RequestMapping(value = "/retrievePassword", method = RequestMethod.POST)
    ResponseEntity<?> retrievePassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, InvalidPasswordSignatureException, ExpiredTimestampException, DuplicateRequestException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyPasswordFetchSignature(input);

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
                if(Long.valueOf(p.timestamp) >
                        Long.valueOf(maximum.timestamp)) {
                    maximum = p;
                }
            }
            Password p = sec.getPasswordReadyToSend(maximum);
            return new ResponseEntity<>(p, null, HttpStatus.OK);
        }
    }


    @RequestMapping(value = "/password", method = RequestMethod.PUT)
    ResponseEntity<?> addPassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, ExpiredTimestampException, DuplicateRequestException, InvalidPasswordSignatureException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException {
        String fingerprint = this.validateUser(input.publicKey);
        sec.verifyPasswordInsertSignature(input);

        System.out.println(input);

        Password[] retrieved = call.putPassword(sec.getPasswordReadyToSend(new Password(input)));

        if (!enoughResponses(retrieved)) {
            System.out.println("Not enough responses from other replicas");
            return new ResponseEntity<>(null, null, HttpStatus.CONFLICT);
        } else {
            return this.userRepository.findByFingerprint(fingerprint).map(user -> {

                Password newPwd = passwordRepository.save(new Password(
                    user,
                    input.domain,
                    input.username,
                    input.password,
                    input.versionNumber,
                    input.deviceId,
                    input.pwdSignature,
                    input.timestamp,
                    input.nonce,
                    input.reqSignature
                ));

                System.out.println("New password registered. ID: " + newPwd.getId());

                Password p = null;
                try {
                    p = sec.getPasswordReadyToSend(newPwd);
                } catch (NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException | KeyStoreException | InvalidKeyException e) {
                    e.printStackTrace();
                }

                return new ResponseEntity<>(p, null, HttpStatus.CREATED);

            }).orElse(new ResponseEntity<>(new Password(), null, HttpStatus.CONFLICT)); // PWD already exist

        }
    }

    private boolean enoughResponses(Object[] retrieved) {
        int n = call.size();
        /* If there were more responses than the number of faults we tolerate, then we will proceed.
        *  The expression (2.0 / 3.0) * n - 1.0 / 6.0) is N = 3f + 1 solved in order to F
        */
        System.out.println(countNotNull(retrieved));
        return countNotNull(retrieved) > (2.0 / 3.0) * n - 1.0 / 6.0;
    }

    private int countNotNull(Object[] array) {
        int count = 0;
        for (Object o : array) if (o != null) count++;
        return count;
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

    @ResponseStatus(value= HttpStatus.BAD_REQUEST, reason="Something is wrong.")
    @ExceptionHandler({IOException.class})
    public void ioException() {
        System.err.println("Something is wrong.");
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