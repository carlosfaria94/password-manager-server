package pt.ulisboa.tecnico.meic.sec;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.Optional;

public interface PasswordRepository extends JpaRepository<Password, Long> {
    Collection<Password> findByUserFingerprintAndDomainAndUsername(String fingerprint, String domain, String username);

    Optional<Password> findByUserFingerprintAndDomainAndUsernameAndVersionNumber(
            String fingerprint, String domain, String username, String versionNumber
    );

    void deleteById(Integer id);

}