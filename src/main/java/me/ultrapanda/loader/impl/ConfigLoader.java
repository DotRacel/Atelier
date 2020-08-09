package me.ultrapanda.loader.impl;

import me.ultrapanda.Atelier;
import me.ultrapanda.config.LoadedConfig;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.loader.Loader;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.role.LoadedRole;
import me.ultrapanda.role.Role;
import me.ultrapanda.script.ScriptObject;
import me.ultrapanda.utils.FileUtil;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ConfigLoader implements Loader {
    private final static AtelierLogger logger = Atelier.atelierLogger;
    private final static AtelierDatabase database = Atelier.atelierDatabase;

    private final File baseFolder;

    private List<LoadedConfig> configs = new ArrayList<>();

    public ConfigLoader(File file){
        this.baseFolder = file;

        refresh();
    }

    @Override
    public void refresh() {
        configs = new ArrayList<>();

        int count = 0;

        database.refreshRoleCache();
        for(Role role : database.cachedRoles){
            File configFile = new File(baseFolder.getAbsolutePath() + File.separator + role.getRoleName() + File.separator + "config.txt");

            if(!configFile.exists()){
                logger.warn("用户组 " + role.getRoleName() + " 不存在配置文件, 已经忽略.");
                configs.add(new LoadedConfig(role, null));
            }else {
                try {
                    configs.add(new LoadedConfig(role, FileUtil.readFile(configFile, false)));
                    count ++;
                } catch (IOException ioException) {
                    logger.warn("加载用户组配置时出现未预料的错误.");
                    ioException.printStackTrace();
                }
            }
        }

        logger.info("成功刷新用户组配置，成功加载了 " + count + " 个配置.");
    }

    public String getConfigByName(String name){
        for (LoadedConfig config : configs) {
            if(config.getRole().getRoleName().equalsIgnoreCase(name)) return config.getText();
        }

        return null;
    }
}
