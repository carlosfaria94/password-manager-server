package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

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
     * @param input - username, password
     * @return
     */
    @RequestMapping(method = RequestMethod.POST)
    ResponseEntity<?> registerUser(@RequestBody User input) {
        // Verify first if username is already taken
        if(this.userRepository.findByUsername(input.username).isPresent()) {
            // User exist. Return NOT FOUND header code
            return new ResponseEntity<>("username already taken", null, HttpStatus.CONFLICT);
        } else {
            User result = userRepository.save(new User(
                    input.username, input.password));

            URI location = ServletUriComponentsBuilder
                    .fromCurrentRequest().path("/{username}")
                    .buildAndExpand(result.getUsername()).toUri();

            return ResponseEntity.created(location).build();
        }

    }

    /**
     * Get user information and also return the user passwords
     * @param username - Identification of the user
     * @return User
     */
    @RequestMapping(method = RequestMethod.GET, value = "/{username}")
    User getUser(@PathVariable String username) {
        return this.userRepository.findByUsername(username).orElseThrow(
                () -> new UserNotFoundException(username));
    }

    private void validateUser(String username) {
        this.userRepository.findByUsername(username).orElseThrow(
                () -> new UserNotFoundException(username));
    }
}
