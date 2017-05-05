package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.UUID;

@Entity
public class Password implements Comparable{

    @Transient
    public String publicKey;
    @Transient
    public String serverPublicKey;
    public String domain;
    public String username;
    public String password;
    public String iv;
    @Column(length = 500)
    public String pwdSignature;
    public String deviceId;
    public String versionNumber;
    @Transient
    public String timestamp;
    @Transient
    public String nonce;
    @Transient
    public String reqSignature;
    @JsonIgnore
    @ManyToOne
    private User user;
    @Id
    @GeneratedValue
    private Integer id;

    Password() { // jpa only
    }

    public Password(Password another) {
        this.publicKey = another.publicKey;
        this.serverPublicKey = another.serverPublicKey;
        this.domain = another.domain;
        this.username = another.username;
        this.password = another.password;
        this.pwdSignature = another.pwdSignature;
        this.deviceId = another.deviceId;
        this.versionNumber = another.versionNumber;
        this.timestamp = another.timestamp;
        this.nonce = another.nonce;
        this.reqSignature = another.reqSignature;
    }

    public Password(User user, String domain, String username, String password, String versionNumber, String deviceId, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.user = user;
        this.versionNumber = versionNumber;
        this.deviceId = deviceId;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public Password(String publicKey, String domain, String username, String password, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public Password(String publicKey, String domain, String username, String password, String versionNumber, String deviceId, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.versionNumber = versionNumber;
        this.deviceId = deviceId;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public Password(String serverPublicKey, String publicKey, String domain, String username, String password, String versionNumber, String deviceId, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.serverPublicKey = serverPublicKey;
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.versionNumber = versionNumber;
        this.deviceId = deviceId;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public User getUser() {
        return user;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "Password{" +
                "user=" + user +
                ", id=" + id +
                ", publicKey='" + publicKey + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", domain='" + domain + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", versionNumber='" + versionNumber + '\'' +
                ", deviceId='" + deviceId + '\'' +
                ", pwdSignature='" + pwdSignature + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", nonce='" + nonce + '\'' +
                ", reqSignature='" + reqSignature + '\'' +
                '}';
    }


    @Override
    public int compareTo(Object o) {
        System.out.println(o.getClass().getSimpleName());
        if (o instanceof Password) {
            Password other = (Password) o;
            int comparison = Integer.valueOf(other.versionNumber)
                    - Integer.valueOf(this.versionNumber);
            if (comparison == 0) {
                return UUID.fromString(other.deviceId).compareTo(UUID.fromString(this.deviceId));
            } else return comparison;
        } else throw new RuntimeException("Not a Password");
    }
}