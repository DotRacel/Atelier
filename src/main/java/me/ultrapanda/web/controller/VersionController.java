package me.ultrapanda.web.controller;

import com.blade.mvc.RouteContext;
import com.blade.mvc.annotation.Path;
import com.blade.mvc.annotation.Route;
import com.blade.mvc.http.HttpMethod;
import lombok.SneakyThrows;
import me.ultrapanda.Atelier;

@Path
public class VersionController {
    @SneakyThrows
    @Route(value = "/version", method = HttpMethod.GET)
    public void version(RouteContext ctx){
        ctx.text(Atelier.VERSION);
    }
}
