package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidPublicKeyException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping("/")
class UserRestController {

    private final UserRepository userRepository;
    private final String serverName = System.getenv("SERVER_NAME");

    @Autowired
    UserRestController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Register a new user
     *
     * @param input - fingerprint, publickey
     * @return user created and HTTP CREATED code
     */
    @RequestMapping(method = RequestMethod.POST)
    ResponseEntity<?> registerUser(@RequestBody User input) throws ArrayIndexOutOfBoundsException, NoSuchAlgorithmException, NullPointerException, CertificateException, KeyStoreException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        try {
            Security sec = new Security("keystore-" + serverName + ".jceks", "batata".toCharArray()); //same as password controller
            String fingerprint = sec.generateFingerprint(input.publicKey);
            sec.verifyPublicKeySignature(input);

            if (!userRepository.findByFingerprint(fingerprint).isPresent()) {
                User newUser = userRepository.save(new User(fingerprint));
                return new ResponseEntity<>(newUser, null, HttpStatus.CREATED);
            }
            return new ResponseEntity<>(null, null, HttpStatus.CONFLICT);
        } catch (InvalidRequestSignatureException e) {
            return new ResponseEntity<>(null, null, HttpStatus.CONFLICT);
        }
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

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Invalid Public Key.")
    @ExceptionHandler({InvalidPublicKeyException.class})
    public void invalidPublicKeyException() {
        System.err.println("Invalid Public Key.");
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Invalid Signature.")
    @ExceptionHandler({SignatureException.class, ArrayIndexOutOfBoundsException.class})
    public void signatureException() {
        System.err.println("Invalid Signature.");
    }
}
