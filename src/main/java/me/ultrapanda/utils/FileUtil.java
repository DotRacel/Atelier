package me.ultrapanda.utils;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileUtil {
    /**
     * From: https://www.cnblogs.com/shaosks/p/9625878.html
     */
    public static List<File> getFiles(String path) {
        List<File> files = new ArrayList<>();
        File file = new File(path);
        File[] tempList = file.listFiles();

        for (File value : tempList) {
            if (value.isFile()) {
                files.add(value);
            }
        }
        return files;
    }

    public static String readFile(File file, boolean lineByLine) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        String line = bufferedReader.readLine();

        while(line != null){
            stringBuilder.append(line);
            if(lineByLine) stringBuilder.append("\n");
            line = bufferedReader.readLine();
        }

        return stringBuilder.toString();
    }

    /**
     * FROM https://blog.csdn.net/menghuanzhiming/article/details/78047914
     *
     * @param f
     * @return
     * @throws IOException
     */
    public static byte[] toByteArray(File f) throws IOException {
        if (!f.exists()) {
            throw new FileNotFoundException(f.getName());
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream((int) f.length());
        BufferedInputStream in = null;
        try {
            in = new BufferedInputStream(new FileInputStream(f));
            int buf_size = 1024;
            byte[] buffer = new byte[buf_size];
            int len = 0;
            while (-1 != (len = in.read(buffer, 0, buf_size))) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            bos.close();
        }
    }

    public static void bufferedWriteFile(File file, String string) throws IOException {
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file, false));
        bufferedWriter.write(string);
        bufferedWriter.close();
    }
}
