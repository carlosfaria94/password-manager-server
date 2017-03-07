package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

@RestController
@RequestMapping("/password")
class PasswordRestController {

    private final PasswordRepository passwordRepository;

    private final UserRepository userRepository;

    @Autowired
    PasswordRestController(PasswordRepository passwordRepository,
                           UserRepository userRepository) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
    }

    @RequestMapping(method = RequestMethod.POST)
    Collection<Password> readPassword(@RequestBody String publicKey,
                                      @RequestBody String domain,
                                      @RequestBody String username) throws NoSuchAlgorithmException {
        Security sec = new Security();
        String fingerprint = sec.generateFingerprint(publicKey);
        this.validateUser(fingerprint);

        System.out.println(domain + username);

        return this.passwordRepository.findByUserFingerprint(fingerprint);
    }

    @RequestMapping(method = RequestMethod.PUT)
    ResponseEntity<?> addPassword(@PathVariable String publicKey, @RequestBody Password input) {

        // TODO: Pegar na public key e gerar o fingerprint
        String fingerprint = "tt";

        this.validateUser(fingerprint);
        return this.userRepository
                .findByFingerprint(fingerprint)
                .map(user -> {
                    Password result = passwordRepository.save(new Password(user,
                            input.domain, input.username, input.password));

                    URI location = ServletUriComponentsBuilder
                            .fromCurrentRequest().path("/{id}")
                            .buildAndExpand(result.getId()).toUri();

                    return ResponseEntity.created(location).build();
                })
                .orElse(ResponseEntity.noContent().build());

    }

    private void validateUser(String fingerprint) {
        this.userRepository.findByFingerprint(fingerprint).orElseThrow(
                () -> new UserNotFoundException());
    }

    @ResponseStatus(value= HttpStatus.INTERNAL_SERVER_ERROR, reason="Cryptographic algorithm is not available.")
    @ExceptionHandler({NoSuchAlgorithmException.class})
    public void noAlgorithm() {
        // Nothing to do
    }
}