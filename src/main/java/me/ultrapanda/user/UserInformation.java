package me.ultrapanda.user;

import me.ultrapanda.Atelier;
import me.ultrapanda.loader.impl.InformationLoader;

public class UserInformation {
    private String username;

    private String role;
    private String ownedRole;

    private String configLastUpdate;

    private String latestVersion;

    private String changelog;
    private String news;

    public UserInformation(User user){
        this.username = user.getUsername();

        this.role = user.getRole();
        this.ownedRole = user.getOwnedRole();

        this.latestVersion = Atelier.VERSION;

        this.changelog = Atelier.informationLoader.getChangelog();
        this.news = Atelier.informationLoader.getNews();

        String lastUpdate = Atelier.configLoader.getLastUpdateDataByName(role);
        this.configLastUpdate = lastUpdate.isEmpty() ? "None" : lastUpdate;
    }
}
