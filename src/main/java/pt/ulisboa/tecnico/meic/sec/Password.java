package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;

@Entity
public class Password extends SecureEntity {

    @JsonIgnore
    @ManyToOne
    private User user;

    @Id
    @GeneratedValue
    private Integer id;

    @Transient
    public String publicKey;

    public String domain;
    public String username;
    public String password;

    @Column(length = 500)
    public String pwdSignature;

    public String iv;
    public String deviceId;
    public String versionNumber;
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

    Password() { // jpa only
    }

    public Password(User user, String domain, String username, String password, String versionNumber, String deviceId,
                    String iv, String pwdSignature, String timestamp, String nonce, String reqSignature) {
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.user = user;
        this.versionNumber = versionNumber;
        this.deviceId = deviceId;
        this.iv = iv;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public Password(String publicKey, String domain, String username, String password, String pwdSignature,
                    String timestamp, String nonce, String reqSignature) {
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    public Password(String publicKey, String domain, String username, String password, String versionNumber,
                    String deviceId,  String iv, String pwdSignature, String timestamp, String nonce,
                    String reqSignature) {
        this.publicKey = publicKey;
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.versionNumber = versionNumber;
        this.deviceId = deviceId;
        this.iv = iv;
        this.pwdSignature = pwdSignature;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.reqSignature = reqSignature;
    }

    @Override
    public String[] getFieldsReadyToSend(){
        return new String[]{
                publicKey,
                domain,
                username,
                password,
                versionNumber,
                iv,
                pwdSignature,
                timestamp,
                nonce,
        };
    }

    @Override
    public String[] getInsertFields() {
        return new String[]{
                publicKey,
                domain,
                username,
                password,
                versionNumber,
                deviceId,
                iv,
                pwdSignature,
                timestamp,
                nonce
        };
    }

    @Override
    public String[] getRetrieveFields(){
        return new String[]{
                publicKey,
                domain,
                username,
                pwdSignature,
                timestamp,
                nonce
        };
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
                ", deviceId='" + deviceId + '\'' +
                ", versionNumber='" + versionNumber + '\'' +
                ", iv='" + iv + '\'' +
                ", pwdSignature='" + pwdSignature + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", nonce='" + nonce + '\'' +
                ", reqSignature='" + reqSignature + '\'' +
                '}';
    }
}