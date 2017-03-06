package pt.ulisboa.tecnico.meic.sec;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.util.HashSet;
import java.util.Set;

@Entity
public class User {

    @Id
    @GeneratedValue
    private Long id;

    public String publicKey;

    @OneToMany(mappedBy = "user")
    private Set<Password> passwords = new HashSet<>();

    public Long getId() {
        return id;
    }

    public Set<Password> getPasswords() {
        return passwords;
    }

    public User(String publicKey) {
        this.publicKey = publicKey;
    }

    User() { // jpa only
    }
}
