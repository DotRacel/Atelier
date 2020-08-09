package me.ultrapanda.config;

import lombok.Getter;
import me.ultrapanda.role.Role;

public class LoadedConfig {
    @Getter private final Role role;
    @Getter private final String text;

    public LoadedConfig(Role role, String text){
        this.role = role;
        this.text = text;
    }
}
