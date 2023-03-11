package com.cos.jwt.model;

import lombok.Data;
import lombok.Getter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Data
public class User {

    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String username;
    private String password;
    private String roles;

    public List<String> getRoleList(){ // 두개이상일경우
        if(this.roles.length() > 0) {
            return Arrays.asList(this.roles.split("."));
        }
        return new ArrayList<>();
    }

}
