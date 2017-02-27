package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.Collection;

@RestController
@RequestMapping("/{username}/passwords")
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
    Collection<Password> readPasswords(@PathVariable String username) {
        this.validateUser(username);
        return this.passwordRepository.findByUserUsername(username);
    }

    @RequestMapping(method = RequestMethod.POST)
    ResponseEntity<?> addPassword(@PathVariable String username, @RequestBody Password input) {
        this.validateUser(username);

        return this.userRepository
                .findByUsername(username)
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

    @RequestMapping(method = RequestMethod.GET, value = "/{passwordId}")
    Password readPassword(@PathVariable String username, @PathVariable Long passwordId) {
        this.validateUser(username);
        return this.passwordRepository.findOne(passwordId);
    }

    private void validateUser(String username) {
        this.userRepository.findByUsername(username).orElseThrow(
                () -> new UserNotFoundException(username));
    }
}