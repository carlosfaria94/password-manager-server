package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.Optional;

@RestController
class PasswordRestController {

    private final PasswordRepository passwordRepository;

    private final UserRepository userRepository;

    @Autowired
    PasswordRestController(PasswordRepository passwordRepository,
                           UserRepository userRepository) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
    }

    @RequestMapping(value = "/retrievePassword", method = RequestMethod.POST)
    ResponseEntity<?> retrievePassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException {
        this.validateUser(input.publicKey);

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
    ResponseEntity<?> addPassword(@RequestBody Password input) throws NoSuchAlgorithmException, NullPointerException {

        String fingerprint = this.validateUser(input.publicKey);

        return this.userRepository
                .findByFingerprint(fingerprint)
                .map(user -> {
                    // TODO: If <domain,username> already exist, update.

                    Timestamp now = new Timestamp(System.currentTimeMillis());

                    Password newPwd = passwordRepository.save(new Password(user,
                            input.domain, input.username, input.password, input.digest, now));

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
        Security sec = new Security();
        String fingerprint = sec.generateFingerprint(publicKey);
        this.userRepository.findByFingerprint(fingerprint).orElseThrow(
                () -> new UserNotFoundException());
        return fingerprint;
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