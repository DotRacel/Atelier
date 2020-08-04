package me.ultrapanda.role;

import lombok.Getter;
import lombok.Setter;

public class Role {
    private String id;

    @Getter @Setter private String roleName;

    public Role(){}

    public Role(String roleName){
        this.roleName = roleName;
    }
}
