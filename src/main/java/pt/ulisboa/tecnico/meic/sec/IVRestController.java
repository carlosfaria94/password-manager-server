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
import java.util.Optional;

@RestController
class IVRestController {

    private final IVRepository ivRepository;

    private final UserRepository userRepository;
    private final String keystorePath;
    private final String keystorePwd;
    private final String serverName = System.getenv("SERVER_NAME");

    private Security sec;

    @Autowired
    IVRestController(IVRepository ivRepository,
                     UserRepository userRepository) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.ivRepository = ivRepository;
        this.userRepository = userRepository;
        keystorePath = "keystore-" + serverName + ".jceks";
        keystorePwd = "batata";
        sec = new Security(keystorePath, keystorePwd.toCharArray());
    }

    @RequestMapping(value = "/retrieveIv", method = RequestMethod.POST)
    ResponseEntity<?> retrieveIv(@RequestBody IV input) throws NoSuchAlgorithmException, NullPointerException, InvalidPasswordSignatureException, ExpiredTimestampException, DuplicateRequestException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        String fingerprint = this.validateUser(input.publicKey);

        Optional<IV> iv = this.ivRepository.findByUserFingerprintAndHash(
                fingerprint,
                input.hash
        );
        if (iv.isPresent()) {
            IV _iv = sec.getIVReadyToSend(iv.get());
            System.out.println(_iv);
            return new ResponseEntity<>(_iv, null, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null, null, HttpStatus.NOT_FOUND);
        }
    }


    @RequestMapping(value = "/iv", method = RequestMethod.PUT)
    ResponseEntity<?> addIV(@RequestBody IV input) throws NoSuchAlgorithmException, NullPointerException, ExpiredTimestampException, DuplicateRequestException, InvalidPasswordSignatureException, InvalidKeySpecException, InvalidRequestSignatureException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException {
        String fingerprint = this.validateUser(input.publicKey);

        System.out.println(input);

        return this.userRepository.findByFingerprint(fingerprint).map(user -> {
            IV newIV = null;

            /*
             To update the password, we first search for user passwords and see if domain,username already exist in DB.
             If true, we delete the pwd and save the new pwd
             If false, no pwd founded, so we create a new pwd
              */
            Optional<IV> iv = ivRepository.findByUserFingerprintAndHash(
                    fingerprint,
                    input.hash
            );
            if (iv.isPresent()) {
                System.out.println("IV já existe, será substituída");

                ivRepository.delete(iv.get());

                newIV = ivRepository.save(new IV(
                        user,
                        input.hash,
                        input.value
                ));

                System.out.println("IV updated. ID: " + newIV.getId());

            } else {
                newIV = ivRepository.save(new IV(
                        user,
                        input.hash,
                        input.value
                ));

                System.out.println("New IV registered. ID: " + newIV.getId());
            }

            IV _iv = null;
            try {
                _iv = sec.getIVReadyToSend(newIV);
            } catch (NoSuchAlgorithmException | UnrecoverableKeyException | SignatureException | KeyStoreException | InvalidKeyException e) {
                e.printStackTrace();
            }

            return new ResponseEntity<>(_iv, null, HttpStatus.CREATED);
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

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Request is not correctly signed")
    @ExceptionHandler({InvalidRequestSignatureException.class})
    public void invalidRequestSignatureException() {
        System.err.println("Request is not correctly signed.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Password is not correctly signed")
    @ExceptionHandler({InvalidPasswordSignatureException.class})
    public void invalidPasswordSignatureException() {
        System.err.println("Password is not correctly signed.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Request expired")
    @ExceptionHandler({ExpiredTimestampException.class})
    public void expiredTimestampException() {
        System.err.println("Request expired.");
    }

    @ResponseStatus(value = HttpStatus.NOT_ACCEPTABLE, reason = "Request already received")
    @ExceptionHandler({DuplicateRequestException.class})
    public void duplicateRequestException() {
        System.err.println("Request already received");
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Something is missing.")
    @ExceptionHandler({NullPointerException.class})
    public void nullException() {
        System.err.println("Something is missing.");
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Cryptographic algorithm is not available.")
    @ExceptionHandler({NoSuchAlgorithmException.class})
    public void noAlgorithm() {
        System.err.println("Cryptographic algorithm is not available.");
    }
}