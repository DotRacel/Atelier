package me.ultrapanda.utils;

import me.ultrapanda.Atelier;
import me.ultrapanda.logger.AtelierLogger;
import org.luaj.vm2.Globals;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.lib.jse.JsePlatform;

import java.io.File;

public class LuaCipher {
    private final static AtelierLogger logger = Atelier.atelierLogger;

    private final LuaValue ENCRYPT;
    private final LuaValue DECRYPT;

    public LuaCipher(File luaScriptFile) {
        if (!luaScriptFile.exists()){
            logger.error("Lua Cipher Library doesn't exist.");
            System.exit(-1);
        }

        Globals globals = JsePlatform.standardGlobals();
        LuaValue AES_INSTANCE = globals.loadfile(luaScriptFile.getName()).call();

        ENCRYPT = AES_INSTANCE.get(LuaValue.valueOf("encrypt"));
        DECRYPT = AES_INSTANCE.get(LuaValue.valueOf("decrypt"));
        logger.info("Atelier 加密初始化成功.");
    }

    public String encrypt(String str, int key1, int key2){
        LuaValue[] arguments = new LuaValue[] {
                LuaValue.valueOf(str),
                LuaValue.valueOf(key1),
                LuaValue.valueOf(key2),
        };

        return ENCRYPT.invoke(LuaValue.varargsOf(arguments)).toString();
    }

    public String decrypt(String str, int key1, int key2){
        LuaValue[] arguments = new LuaValue[] {
                LuaValue.valueOf(str),
                LuaValue.valueOf(key1),
                LuaValue.valueOf(key2),
        };

        return DECRYPT.invoke(LuaValue.varargsOf(arguments)).toString();
    }
}
