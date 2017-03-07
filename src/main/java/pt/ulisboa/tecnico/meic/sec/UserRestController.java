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
    ResponseEntity<?> registerUser(@RequestBody User input) throws NoSuchAlgorithmException {
        // TODO: Verificar se a public key é submetida
        Security sec = new Security();
        String fingerprint = sec.generateFingerprint(input.publicKey);

        User newUser = userRepository.save(new User(fingerprint));
        return new ResponseEntity<>(newUser, null, HttpStatus.CREATED);
    }

    @ResponseStatus(value= HttpStatus.INTERNAL_SERVER_ERROR, reason="Cryptographic algorithm is not available.")
    @ExceptionHandler({NoSuchAlgorithmException.class})
    public void noAlgorithm() {
        // Nothing to do
    }
}
