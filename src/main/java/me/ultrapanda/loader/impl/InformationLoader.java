package me.ultrapanda.loader.impl;

import lombok.Getter;
import me.ultrapanda.Atelier;
import me.ultrapanda.loader.Loader;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.utils.FileUtil;

import java.io.File;
import java.io.IOException;

public class InformationLoader implements Loader {
    private final static AtelierLogger logger = Atelier.atelierLogger;

    private final File baseFolder;

    @Getter private String news;
    @Getter private String changelog;

    public InformationLoader(File file){
        this.baseFolder = file;

        refresh();
    }

    @Override
    public void refresh() {
        File newsFile = new File(baseFolder.getAbsolutePath() + File.separator + "news.txt");
        File changelogFile = new File(baseFolder.getAbsolutePath() + File.separator + "changelog.txt");

        try{
            newsFile.createNewFile();
            changelogFile.createNewFile();

            news = FileUtil.readFile(newsFile, true);
            changelog = FileUtil.readFile(changelogFile, true);

            logger.info("成功刷新本地信息.");
        }catch (IOException ioException){
            logger.error("加载本地信息时出现错误!");
            ioException.printStackTrace();
        }
    }
}
