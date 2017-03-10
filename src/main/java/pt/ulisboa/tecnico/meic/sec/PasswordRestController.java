package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pt.ulisboa.tecnico.meic.sec.exception.DuplicateRequestException;
import pt.ulisboa.tecnico.meic.sec.exception.ExpiredTimestampException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidPasswordSignatureException;
import pt.ulisboa.tecnico.meic.sec.exception.InvalidRequestSignatureException;

import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.Optional;

@RestController
class PasswordRestController {

    private final PasswordRepository passwordRepository;

    private final UserRepository userRepository;

    private Security sec = new Security();

    @Autowired
    PasswordRestController(PasswordRepository passwordRepository,
                           UserRepository userRepository) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
    }

    @RequestMapping(value = "/retrievePassword", method = RequestMethod.POST)
    ResponseEntity<?> retrievePassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, InvalidPasswordSignatureException, ExpiredTimestampException, DuplicateRequestException {
        this.validateUser(input.publicKey);
        this.validatePasswordSignature(input);

        // TODO: If 2 identical <domain,username> exist, this will not work fine.
        // TODO: Can't exist 2 or more identical <domain, username> in server
        Optional<Password> pwd = this.passwordRepository.findByDomainAndUsername(input.domain, input.username);
        if (pwd.isPresent()) {
            return new ResponseEntity<>(pwd.get(), null, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null, null, HttpStatus.NOT_FOUND);
        }
    }

    @RequestMapping(value = "/password", method = RequestMethod.PUT)
    ResponseEntity<?> addPassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException, ExpiredTimestampException, DuplicateRequestException {

        String fingerprint = this.validateUser(input.publicKey);
        this.validatePasswordSignature(input);

        return this.userRepository
                .findByFingerprint(fingerprint)
                .map(user -> {
                    // TODO: If <domain,username> already exist, update.

                    Timestamp now = new Timestamp(System.currentTimeMillis());

                    //FIXME
                    Password newPwd = passwordRepository.save(new Password(user,
                            input.domain, input.username, input.password, input.pwdSignature, now));

                    System.out.println(now.toString() + ": New password registered. ID: " + newPwd.getId());

                    return new ResponseEntity<>(newPwd, null, HttpStatus.CREATED);
                })
                .orElse(ResponseEntity.noContent().build());

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

    /**
     * Verifies if request message correctly signed
     *
     * @param password
     * @return void
     * @throws NoSuchAlgorithmException
     */
    private void validatePasswordSignature(Password password) throws DuplicateRequestException, ExpiredTimestampException, NoSuchAlgorithmException {
        sec.verifyPasswordSignature(password);
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Request is not correctly signed")
    @ExceptionHandler({InvalidRequestSignatureException.class})
    public void invalidRequestSignatureException() {
        // Nothing to do
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Password is not correctly signed")
    @ExceptionHandler({InvalidPasswordSignatureException.class})
    public void invalidPasswordSignatureException() {
        // Nothing to do
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Request expired")
    @ExceptionHandler({ExpiredTimestampException.class})
    public void expiredTimestampException() {
        // Nothing to do
    }

    @ResponseStatus(value= HttpStatus.NOT_ACCEPTABLE, reason="Request already received")
    @ExceptionHandler({DuplicateRequestException.class})
    public void duplicateRequestException() {
        // Nothing to do
    }

    @ResponseStatus(value= HttpStatus.BAD_REQUEST, reason="Something is missing.")
    @ExceptionHandler({NullPointerException.class})
    public void nullException() {
        // Nothing to do
    }

    @ResponseStatus(value= HttpStatus.BAD_REQUEST, reason="Cryptographic algorithm is not available.")
    @ExceptionHandler({NoSuchAlgorithmException.class})
    public void noAlgorithm() {
        // Nothing to do
    }
}