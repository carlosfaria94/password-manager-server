package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.sql.Timestamp;
import java.time.Instant;

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

    public Password(User user, String domain, String username, String password, String pwdSignature, Timestamp registered, Instant timestamp, String nonce, String reqSignature) {
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.user = user;
        this.pwdSignature = pwdSignature;
        this.registered = registered;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }


    @Transient
    public String publicKey;

    public String domain;
    public String username;
    public String password;
    public String pwdSignature;
    public Timestamp registered;

    public Instant timestamp;
    public String nonce;
    public String reqSignature;

    public User getUser() {
        return user;
    }

    public Integer getId() {
        return id;
    }

    @Override
    public String toString() {
        //FIXME
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