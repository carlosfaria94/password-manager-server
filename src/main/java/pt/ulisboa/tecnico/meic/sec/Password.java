package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;

@Entity
public class Password {

    @Transient
    public String publicKey;
    public String domain;
    public String username;
    public String password;
    @Column(length = 500)
    public String pwdSignature;
    public String deviceId;
    public String versionNumber;
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
                ", versionNumber='" + versionNumber + '\'' +
                ", deviceId='" + deviceId + '\'' +
                ", pwdSignature='" + pwdSignature + '\'' +
                ", nonce='" + nonce + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", reqSignature='" + reqSignature + '\'' +
                '}';
    }
}