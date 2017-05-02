package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;

@Entity
public class IV {

    @JsonIgnore
    @ManyToOne
    private User user;

    @Id
    @GeneratedValue
    private Integer id;

    @Transient
    public String publicKey;

    public String hash;
    public String value;
    @Transient
    public String timestamp;
    @Transient
    public String nonce;
    @Transient
    public String reqSignature;

    public User getUser() {
        return user;
    }

    public Integer getId() {
        return id;
    }

    IV() { // jpa only
    }

    public IV(User user, String hash, String value) {
        this.user = user;
        this.hash = hash;
        this.value = value;
    }

    public IV(String hash, String value) {
        this.hash = hash;
        this.value = value;
    }

    @Override
    public String toString() {
        return "IV{" +
                "user=" + user +
                ", id=" + id +
                ", publicKey='" + publicKey + '\'' +
                ", hash='" + hash + '\'' +
                ", value='" + value + '\'' +
                '}';
    }
}