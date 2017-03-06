package pt.ulisboa.tecnico.meic.sec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

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
     * @param input - username, password
     * @return user created and HTTP CREATED code
     */
    @RequestMapping(method = RequestMethod.POST)
    ResponseEntity<?> registerUser(@RequestBody User input) {
        // TODO: Verificar se a public key é submetida

        User newUser = userRepository.save(new User(input.publicKey));

        return new ResponseEntity<>(newUser, null, HttpStatus.CREATED);
    }
}
