package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping("/")
class UserRestController {

    private final UserRepository userRepository;

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
    ResponseEntity<?> registerUser(@RequestBody User input) throws NoSuchAlgorithmException, NullPointerException {
        Security sec = new Security();
        String fingerprint = sec.generateFingerprint(input.publicKey);

        if (!userRepository.findByFingerprint(fingerprint).isPresent()) {
            User newUser = userRepository.save(new User(fingerprint));
            return new ResponseEntity<>(newUser, null, HttpStatus.CREATED);
        }
        return new ResponseEntity<>(null, null, HttpStatus.CONFLICT);
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
