package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
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

    @RequestMapping(method = RequestMethod.GET)
    Collection<Password> readPasswords(@RequestBody String publicKey) {
        this.validateUser(publicKey);
        return this.passwordRepository.findByUserPublicKey(publicKey);
    }

    @RequestMapping(method = RequestMethod.PUT)
    ResponseEntity<?> addPassword(@PathVariable String publicKey, @RequestBody Password input) {
        this.validateUser(publicKey);

        return this.userRepository
                .findByPublicKey(publicKey)
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

    private void validateUser(String publicKey) {
        this.userRepository.findByPublicKey(publicKey).orElseThrow(
                () -> new UserNotFoundException());
    }
}