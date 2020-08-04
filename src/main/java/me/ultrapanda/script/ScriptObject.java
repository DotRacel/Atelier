package me.ultrapanda.script;

import lombok.Getter;

import java.util.Base64;

public class ScriptObject {

    @Getter private final String name;
    @Getter private final byte[] bytes;

    public ScriptObject(String name, byte[] bytes){
        this.name = name;
        this.bytes = bytes;
    }

    public String toBase64(){
        return Base64.getEncoder().encodeToString(bytes);
    }
}
