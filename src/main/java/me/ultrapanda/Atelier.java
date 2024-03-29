package me.ultrapanda;

import me.ultrapanda.console.AtelierConsole;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.loader.Loader;
import me.ultrapanda.loader.impl.ConfigLoader;
import me.ultrapanda.loader.impl.InformationLoader;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.loader.impl.ScriptLoader;
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
    public static ConfigLoader configLoader;
    public static InformationLoader informationLoader;

    public static LuaCipher luaCipher;
    public static Crypto crypto;

    public static String VERSION = "1.5";
    public static File BASE_FOLDER = new File("");

    public static void main(String[] args) {
        atelierLogger.info("正在启动 Atelier 服务 ...");

        // 加密
        luaCipher = new LuaCipher(new File("cipher.lua"));
        crypto = new Crypto();

        // 网页
        atelierWeb.start();

        // 控制台
        atelierConsole.start();

        // 数据库
        atelierDatabase.connect();

        // 加载
        scriptLoader = new ScriptLoader(BASE_FOLDER);
        configLoader = new ConfigLoader(BASE_FOLDER);
        informationLoader = new InformationLoader(BASE_FOLDER);
    }
}