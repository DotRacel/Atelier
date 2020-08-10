package me.ultrapanda.user;

import lombok.Getter;
import lombok.Setter;
import me.ultrapanda.status.UserStatus;

public class User {
    @Getter @Setter private String username = "";
    @Getter @Setter private String password = "";

    @Getter @Setter private String role = "";
    @Getter @Setter private String ownedRole = "";

    @Getter @Setter private String hwid = "";

    @Getter @Setter private UserStatus userStatus = null;

    public User(String username, String password, String role, String hwid, UserStatus userStatus, String ownedRole){
        this.username = username;
        this.password = password;

        this.role = role;
        this.ownedRole = ownedRole;

        this.hwid = hwid;
        this.userStatus = userStatus;
    }

    public User() {}
}
