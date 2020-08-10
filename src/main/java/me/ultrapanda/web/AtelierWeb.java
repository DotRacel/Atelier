package me.ultrapanda.web;

import me.ultrapanda.web.controller.AtelierController;
import me.ultrapanda.web.controller.VersionController;

import static spark.Spark.*;


public class AtelierWeb {
    private final int port;

    public AtelierWeb(int port) {
        this.port = port;
    }

    public void start(){
        port(port);

        get("/atelier", AtelierController.handle_atelier_get);
        post("/atelier", AtelierController.handle_atelier_post);

        get("/version", VersionController.handle_version_request);
    }
}
