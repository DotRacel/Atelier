package me.ultrapanda.web.controller;

import com.google.gson.Gson;
import me.ultrapanda.Atelier;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.script.ScriptObject;
import me.ultrapanda.status.RequestType;
import me.ultrapanda.status.ResponseStatus;
import me.ultrapanda.status.UserStatus;
import me.ultrapanda.user.User;
import me.ultrapanda.user.UserInformation;
import me.ultrapanda.utils.Crypto;
import me.ultrapanda.utils.FileUtil;
import me.ultrapanda.utils.LuaCipher;
import spark.*;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static me.ultrapanda.Atelier.configLoader;
import static me.ultrapanda.Atelier.scriptLoader;

public class AtelierController {
    private final static SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final static int staticKey = 812934;

    private final static Crypto crypto = new Crypto();
    private final static LuaCipher cipher = Atelier.luaCipher;

    private final static Gson gson = new Gson();

    private final static AtelierDatabase atelierDatabase = Atelier.atelierDatabase;
    private final static AtelierLogger logger = Atelier.atelierLogger;

    public static Route handle_atelier_get = (Request request, Response response) -> {
        try{
            Map<String, String> parameters = convertToMap(request.queryMap());

            // 检测请求类型
            String requestType = parameters.get("request");
            if(requestType == null || !(requestType.equals(RequestType.GET_LIST) || requestType.equals(RequestType.GET_LUA) || requestType.equals(RequestType.GET_CONFIG))){
                return(ResponseStatus.BAD_PARAMETERS);
            }

            String username = parameters.get("username");
            String password = parameters.get("password");
            String hwid = parameters.get("hwid");
            String signature = parameters.get("signature");
            String time = parameters.get("time");
            String key = parameters.get("key");

            if(username == null || password == null || hwid == null || signature == null || time == null || key == null){
                return(ResponseStatus.BAD_REQUEST);
            }

            User user = checkUser(username, password, hwid, requestType, signature, time, request, response);

            if(user == null) return(response.body()); // 验证用户
            if(!checkAgent(user, request, response)) return(response.body()); // 验证 UserAgent

            switch (requestType){
                default:
                    return(ResponseStatus.BAD_REQUEST);
                case RequestType.GET_LIST:
                    StringBuilder stringBuilder = new StringBuilder(gson.toJson(new UserInformation(user)) + "\n");

                    String nextLine = "";
                    for(ScriptObject scriptObject : scriptLoader.getScriptObjectsByName(user.getRole())){
                        stringBuilder.append(nextLine).append(scriptObject.getName());
                        nextLine = "\n";
                    }

                    logger.info("用户 " + user.getUsername() + " 登陆成功. [IP:" + request.ip() + "] " + String.format("[%s]", format.format(new Date())));

                    return(cipher.encrypt(stringBuilder.toString(), staticKey, Integer.parseInt(key)));
                case RequestType.GET_LUA:
                    if(parameters.get("script") == null){
                        return(ResponseStatus.BAD_PARAMETERS);
                    }

                    String scriptName = parameters.get("script");
                    if(scriptName == null){
                        return(ResponseStatus.BAD_PARAMETERS);
                    }

                    ScriptObject scriptObject = scriptLoader.getScriptObjectByName(user.getRole(), scriptName);

                    if(scriptObject == null) {
                        return(ResponseStatus.SCRIPT_UNKNOWN);
                    }

                    return(cipher.encrypt(scriptObject.toBase64(), staticKey, Integer.parseInt(key)));
                case RequestType.GET_CONFIG:
                    String config = configLoader.getConfigByName(user.getRole());

                    if(config == null || config.isEmpty()) {
                        return(ResponseStatus.CONFIG_UNKNOWN);
                    }else {
                        // 这里的 static key 和 random key 与其他情况下是本末倒置的.
                        return(cipher.encrypt(config, Integer.parseInt(key), staticKey));
                    }
            }
        }catch (Exception exception){
            logger.error("出现未预料的错误!");
            exception.printStackTrace();
        }

        return ResponseStatus.INTERNAL_ERROR;
    };

    public static Route handle_atelier_post = (Request request, Response response) -> {
        Map<String, String> parameters = gson.fromJson(request.body(), Map.class);

        try{
            // 检测请求类型
            String requestType = parameters.get("request");
            if(requestType == null || !(requestType.equals(RequestType.UPLOAD_CONFIG))){
                return(ResponseStatus.BAD_PARAMETERS);
            }

            String username = parameters.get("username");
            String password = parameters.get("password");
            String hwid = parameters.get("hwid");
            String signature = parameters.get("signature");
            String time = parameters.get("time");

            if(username == null || password == null || hwid == null || signature == null || time == null){
                return(ResponseStatus.BAD_REQUEST);
            }

            User user = checkUser(username, password, hwid, requestType, signature, time, request, response);

            if(user == null) return(response.body()); // 验证用户
            if(!checkAgent(user, request, response)) return(response.body()); // 验证 UserAgent

            switch (requestType) {
                default:
                    return(ResponseStatus.BAD_REQUEST);
                case RequestType.UPLOAD_CONFIG:
                    if(user.getOwnedRole() == null || user.getOwnedRole().isEmpty() || user.getOwnedRole().equals("")){
                        logger.warn("用户 " + user.getUsername() + " 未拥有上传配置文件的权限，却发送了上传配置文件的奇怪请求，怀疑正在破解，已经阻止该操作.");
                        return(ResponseStatus.REQUEST_NOT_ALLOWED);
                    }

                    if(!user.getOwnedRole().equalsIgnoreCase(user.getRole())){
                        logger.warn("用户 " + user.getUsername() + " 尝试将其配置文件上传到与其权限所在组不同的用户组，已阻止该操作，出现这一问题的原因是用户组不同导致的. 请检查.");
                        return(ResponseStatus.REQUEST_NOT_ALLOWED);
                    }
                    File configFile = new File(Atelier.BASE_FOLDER.getAbsolutePath() + File.separator + user.getRole() + File.separator + "config.txt");

                    try{
                        if(!configFile.exists()){
                            configFile.createNewFile();
                        }

                        logger.info("用户 " + user.getUsername() + " 成功为用户组 " + user.getOwnedRole().toUpperCase() + " 上传/更新 配置文件.");

                        FileUtil.bufferedWriteFile(configFile, parameters.get("config"));
                        configLoader.refresh();

                        return(ResponseStatus.REQUEST_RECEIVED);
                    }catch (IOException ioException){
                        logger.error("用户上传配置文件时发生未预料的错误!");
                        ioException.printStackTrace();
                        return(ResponseStatus.INTERNAL_ERROR);
                    }
            }
        }catch (Exception exception) {
            logger.error("出现未预料的错误!");
            exception.printStackTrace();
            return(ResponseStatus.INTERNAL_ERROR);
        }
    };

    private static boolean checkAgent(User user, Request request, Response response){
        // 用户已经完全验证
        if(!request.userAgent().startsWith("Valve/Steam HTTP Client 1.0") || !request.userAgent().contains("no")){
            response.body((ResponseStatus.USER_BANNED));
            atelierDatabase.changeUserStatus(user.getUsername(), UserStatus.BANNED);
            logger.warn("用户 " + user.getUsername() + " 的用户标识不正确，正在尝试破解，已封禁. (" + request.userAgent() + ")");

            return false;
        }else {
            return true;
        }
    }

    private static User checkUser(String username, String password, String hwid, String requestType, String signature, String time, Request request, Response response){
        try{

            // 先验证签名 防止数据库操作造成不必要的性能损失.
            if(!validSignature(username, password, hwid, requestType, time, signature)){
                logger.warn(username + " 提供了一个非法签名. 正确签名: " + crypto.encryptMD5ToString(username + ":" + requestType + ":" + password + ":" + "SIGNATURE" + ":" + hwid + ":" + time));
                response.body(ResponseStatus.INVALID_SIGNATURE);
                return null;
            }

            User user = atelierDatabase.getUserFromName(username);
            if(user == null){
                response.body((ResponseStatus.USER_UNKNOWN));
                return null;
            }

            if(!user.getPassword().equals(password)){
                response.body((ResponseStatus.USER_WRONG_PASSWORD));
                return null;
            }else if(!user.getHwid().equals(hwid)){
                if(hwid.length() != 32){
                    atelierDatabase.changeUserStatus(user.getUsername(), UserStatus.BANNED);
                    logger.warn("用户 " + user.getUsername() + " 提供了一个不合法的HWID，已经将它封禁. IP: " + request.ip());
                    response.body((ResponseStatus.USER_BANNED));
                    return null;
                }

                if(user.getHwid().equals("")){
                    atelierDatabase.setHwid(user.getUsername(), hwid);
                    logger.warn("用户 " + user.getUsername() + " 第一次登陆，HWID设置为了: " + hwid + " IP: " + request.ip());
                }else{
                    logger.warn("用户 " + user.getUsername() + " 的当前HWID不匹配. 已拒绝请求. IP: " + request.ip());
                    response.body((ResponseStatus.USER_WRONG_HWID));
                    return null;
                }
            }else if(user.getUserStatus() == UserStatus.BANNED){
                logger.warn("用户 " + user.getUsername() + " 尝试登陆，但他已被封禁. IP: " + request.ip());
                response.body((ResponseStatus.USER_BANNED));
                return null;
            }

            return user;
        }catch (NoSuchAlgorithmException noSuchAlgorithmException){
            logger.warn("出现无效算法错误.");
            noSuchAlgorithmException.printStackTrace();
            response.body((ResponseStatus.INTERNAL_ERROR));
        }catch (NullPointerException nullPointerException){
            logger.warn("出现空指针错误.");
            nullPointerException.printStackTrace();
            response.body((ResponseStatus.INTERNAL_ERROR));
        }catch (Exception exception){
            logger.warn("出现未预料的错误.");
            exception.printStackTrace();
            response.body((ResponseStatus.INTERNAL_ERROR));
        }

        return null;
    }

    private static boolean validSignature(String username, String password, String hwid, String requestType, String time, String signature) throws NoSuchAlgorithmException {
        return crypto.encryptMD5ToString(username + ":" + requestType + ":" + password + ":" + "SIGNATURE" + ":" + hwid + ":" + time).equals(signature);
    }

    private static Map<String, String> convertToMap(QueryParamsMap queryParamsMap){
        Map<String, String> toReturn = new HashMap<>();
        Map<String, String[]> queryMap = queryParamsMap.toMap();

        for(String string : queryMap.keySet()){
            toReturn.put(string, queryMap.get(string)[0]);
        }

        return toReturn;
    }
}
