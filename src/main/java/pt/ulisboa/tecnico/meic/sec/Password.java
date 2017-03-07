package pt.ulisboa.tecnico.meic.sec;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

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

    public Password(User user, String domain, String username, String password) {
        this.domain = domain;
        this.username = username;
        this.password = password;
        this.user = user;
    }

    public String domain;
    public String username;
    public String password;

    public User getUser() {
        return user;
    }

    public Integer getId() {
        return id;
    }
}