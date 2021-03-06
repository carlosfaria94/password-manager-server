package pt.ulisboa.tecnico.meic.sec;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;

public interface PasswordRepository extends JpaRepository<Password, Long> {
    Collection<Password> findByUserFingerprintAndDomainAndUsername(String fingerprint, String domain, String username);
}