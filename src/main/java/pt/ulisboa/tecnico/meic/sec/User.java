package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

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

    public Long getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    @JsonIgnore
    public String password;
    public String username;

    @OneToMany(mappedBy = "user")
    private Set<Password> passwords = new HashSet<>();

    public Set<Password> getPasswords() {
        return passwords;
    }

    public User(String name, String password) {
        this.username = name;
        this.password = password;
    }

    User() { // jpa only
    }
}
