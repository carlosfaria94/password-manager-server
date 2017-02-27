package pt.ulisboa.tecnico.meic.sec;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Arrays;

@SpringBootApplication
public class ServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServerApplication.class, args);
	}

    @Bean
    CommandLineRunner init(UserRepository userRepository,
                           PasswordRepository passwordRepository) {
        return (evt) -> Arrays.asList(
                "jhoeller,dsyer,pwebb,ogierke,rwinch,mfisher,mpollack,jlong".split(","))
                .forEach(
                        a -> {
                            User user = userRepository.save(new User(a,
                                    "password"));
                            passwordRepository.save(new Password(user,
                                    "http://bookmark.com/1/", a, "pwd2"));
                            passwordRepository.save(new Password(user,
                                    "http://bookmark.com/2/", a, "pwd5"));
                        });
    }
}

@ResponseStatus(HttpStatus.NOT_FOUND)
class UserNotFoundException extends RuntimeException {

	public UserNotFoundException(String userId) {
		super("could not find user '" + userId + "'.");
	}
}