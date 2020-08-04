package me.ultrapanda.role;

import lombok.Getter;
import me.ultrapanda.script.ScriptObject;

import java.util.List;

public class LoadedRole {
    @Getter private final Role role;
    @Getter private final List<ScriptObject> scriptObjects;

    public LoadedRole(Role role, List<ScriptObject> scriptObjects){
        this.role = role;
        this.scriptObjects = scriptObjects;
    }
}
