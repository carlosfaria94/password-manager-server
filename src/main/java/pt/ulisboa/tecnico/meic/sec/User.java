package pt.ulisboa.tecnico.meic.sec;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
public class User {

    public String fingerprint;
    @Transient
    public String signature;
    @Transient
    public String publicKey;
    @Id
    @GeneratedValue
    private Integer id;
    @OneToMany(mappedBy = "user")
    private Set<Password> passwords = new HashSet<>();

    public User(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public User(String publicKey, String signature) {
        this.publicKey = publicKey;
        this.signature = signature;
    }

    User() { // jpa only
    }

    public Integer getId() {
        return id;
    }

    public Set<Password> getPasswords() {
        return passwords;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", fingerprint='" + fingerprint + '\'' +
                ", signature='" + signature + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", passwords=" + passwords +
                '}';
    }
}
