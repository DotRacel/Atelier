package me.ultrapanda.web;

import com.blade.Blade;

public class AtelierWeb {
    private final Blade blade = Blade.of();

    public AtelierWeb(int port) {
        blade.environment().set("server.port", port);
        blade.environment().set("app.thread-name", "Web");
        blade.environment().set("com.blade.logger.rootLevel", "error");
        blade.environment().set("com.blade.logger.shortName", false);
        blade.environment().set("com.blade.logger.showLogName", false);
        blade.environment().set("com.blade.logger.showThread", false);
        blade.environment().set("com.blade.logger.showDate", false);

        blade.environment().set("http.gzip.enable", true);
        blade.environment().set("app.devMode", false);
    }

    public void start(){
        blade.start(AtelierWeb.class);
    }
}
