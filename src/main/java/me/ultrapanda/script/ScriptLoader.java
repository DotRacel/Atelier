package me.ultrapanda.script;

import me.ultrapanda.Atelier;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.role.LoadedRole;
import me.ultrapanda.role.Role;
import me.ultrapanda.utils.FileUtil;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ScriptLoader {
    private final AtelierLogger logger = Atelier.atelierLogger;
    private final AtelierDatabase database = Atelier.atelierDatabase;

    private final File baseFolder;

    private final List<LoadedRole> roleScripts = new ArrayList<>();

    public ScriptLoader(File file){
        this.baseFolder = file;

        refresh();
    }

    public void refresh() {
        roleScripts.clear();

        int count = 0;

        database.refreshRoleCache();
        for(Role role : database.cachedRoles){
            File folder = new File(baseFolder.getAbsolutePath() + File.separator + role.getRoleName());

            if(!folder.exists()){
                logger.warn("用户组的 " + role.getRoleName() + " 文件夹不存在，" + (folder.mkdir() ? "创建成功" : "创建失败") + ".");
            }

            try{
                List<ScriptObject> scriptObjects = loadFilesToScriptObject(new ArrayList<>(FileUtil.getFiles(folder.getAbsolutePath())));

                roleScripts.add(new LoadedRole(role, scriptObjects));
                count = count + scriptObjects.size();
            }catch (Exception exception){
                logger.error("加载脚本时出现错误.");

            }
        }

        logger.info("成功刷新脚本池，成功加载了 " + count + " 个脚本.");
    }

    private List<ScriptObject> loadFilesToScriptObject(List<File> files) throws IOException {
        List<ScriptObject> scriptObjects = new ArrayList<>();

        for(File file : files){
            scriptObjects.add(new ScriptObject(file.getName().split("\\.")[0], FileUtil.toByteArray(file)));
        }

        return scriptObjects;
    }

    public List<ScriptObject> getScriptObjectsByName(String name){
        for(LoadedRole loadedRole : roleScripts){
            if(loadedRole.getRole().getRoleName().equalsIgnoreCase(name)) return loadedRole.getScriptObjects();
        }

        return null;
    }

    public ScriptObject getScriptObjectByName(String roleName, String name){
        for(LoadedRole loadedRole : roleScripts){
            if(roleName.equalsIgnoreCase(loadedRole.getRole().getRoleName())){
                for(ScriptObject scriptObject : loadedRole.getScriptObjects()){
                    if(scriptObject.getName().equalsIgnoreCase(name)){
                        return scriptObject;
                    }
                }
            }
        }

        return null;
    }
}