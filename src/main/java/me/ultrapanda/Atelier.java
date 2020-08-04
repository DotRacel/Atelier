package me.ultrapanda;

import me.ultrapanda.console.AtelierConsole;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.script.ScriptLoader;
import me.ultrapanda.utils.Crypto;
import me.ultrapanda.utils.LuaCipher;
import me.ultrapanda.web.AtelierWeb;

import java.io.File;

public class Atelier {
    public static AtelierLogger atelierLogger = new AtelierLogger();
    public static AtelierConsole atelierConsole = new AtelierConsole("| ");
    public static AtelierDatabase atelierDatabase = new AtelierDatabase("localhost", 27017, "atelier");
    public static AtelierWeb atelierWeb = new AtelierWeb(4755);

    public static ScriptLoader scriptLoader;
    public static LuaCipher luaCipher;
    public static Crypto crypto;

    public static String VERSION = "1.3";

    public static void main(String[] args) {
        luaCipher = new LuaCipher(new File("cipher.lua"));
        crypto = new Crypto();
        atelierWeb.start();

        atelierLogger.info("正在启动 Atelier 服务 ...");
        atelierConsole.start(); // 初始化控制台
        atelierDatabase.connect(); // 连接数据库

        scriptLoader = new ScriptLoader(new File(""));
    }
}