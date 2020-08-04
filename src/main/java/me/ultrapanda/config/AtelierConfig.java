package me.ultrapanda.config;

import me.ultrapanda.Atelier;
import me.ultrapanda.logger.AtelierLogger;

public class AtelierConfig {
    private final String configName;
    private final AtelierLogger logger = Atelier.atelierLogger;

    public AtelierConfig(String configName){
        this.configName = configName;
    }

    public void load(){

        logger.info("Atelier 配置文件加载成功.");
    }
}
