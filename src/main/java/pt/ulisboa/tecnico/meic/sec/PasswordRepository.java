package pt.ulisboa.tecnico.meic.sec;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PasswordRepository extends JpaRepository<Password, Long> {

    @Query(value = "SELECT p FROM Password p where p.user.fingerprint = :fingerprint and p.domain=:domain and p.username=:username")
    Collection<Password>
    findByUserFingerprintAndDomainAndUsername(@Param("fingerprint") String fingerprint,
                                              @Param("domain") String domain,
                                              @Param("username") String username);

    Optional<Password> findByUserFingerprintAndDomainAndUsernameAndVersionNumber(
            String fingerprint, String domain, String username, String versionNumber
    );

    void deleteById(Integer id);

    List<Password> findTop10ByOrderById();
    List<Password> findAll();
}