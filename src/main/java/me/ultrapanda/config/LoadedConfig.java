package me.ultrapanda.config;

import lombok.Getter;
import me.ultrapanda.role.Role;

public class LoadedConfig {
    @Getter private final Role role;
    @Getter private final String text;

    @Getter private final long lastUpdate;

    public LoadedConfig(Role role, String text, long lastUpdate){
        this.role = role;
        this.text = text;

        this.lastUpdate = lastUpdate;
    }
}
