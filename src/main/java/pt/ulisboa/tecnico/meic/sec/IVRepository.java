package pt.ulisboa.tecnico.meic.sec;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IVRepository extends JpaRepository<IV, Long> {
    Optional<IV> findByUserFingerprintAndHash(String fingerprint, String hash);
}