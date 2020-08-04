package me.ultrapanda.logger;

public class AtelierLogger {
    public void info(String string) {
        System.out.println("[~] " + string);
    }

    public void warn(String string){
        System.out.println("[!] " + string);
    }

    public void error(String string){
        System.out.println("[?] " + string);
    }
}
