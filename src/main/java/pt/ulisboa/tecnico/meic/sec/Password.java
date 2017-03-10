package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.sql.Timestamp;

@Entity
public class Password {

    @JsonIgnore
    @ManyToOne
    private User user;

    @Id
    @GeneratedValue
    private Integer id;

    Password() { // jpa only
    }

    public Password(User user, String domain, String username, String password, String digest, Timestamp registered) {
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.user = user;
        this.digest = digest;
        this.registered = registered;
    }


    @Transient
    public String publicKey;

    public String domain;
    public String username;
    public String password;
    public String digest;
    public Timestamp registered;

    public User getUser() {
        return user;
    }

    public Integer getId() {
        return id;
    }

    @Override
    public String toString() {
        return "Password{" +
                "user=" + user +
                ", id=" + id +
                ", publicKey='" + publicKey + '\'' +
                ", domain='" + domain + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", digest='" + digest + '\'' +
                ", registered=" + registered +
                '}';
    }
}