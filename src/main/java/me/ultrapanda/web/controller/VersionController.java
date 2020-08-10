package me.ultrapanda.web.controller;

import me.ultrapanda.Atelier;
import spark.*;

public class VersionController {
    public static Route handle_version_request = (Request request, Response response) -> (Atelier.VERSION);
}
