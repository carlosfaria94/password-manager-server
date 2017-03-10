package pt.ulisboa.tecnico.meic.sec;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
public class User {

    @Id
    @GeneratedValue
    private Integer id;

    public String fingerprint;

    @Transient
    public String publicKey;

    @OneToMany(mappedBy = "user")
    private Set<Password> passwords = new HashSet<>();

    public Integer getId() {
        return id;
    }

    public Set<Password> getPasswords() {
        return passwords;
    }

    public User(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    User() { // jpa only
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", fingerprint='" + fingerprint + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", passwords=" + passwords +
                '}';
    }
}
