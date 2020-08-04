package me.ultrapanda.web.controller;

import com.blade.mvc.RouteContext;
import com.blade.mvc.annotation.Path;
import com.blade.mvc.annotation.Route;
import com.blade.mvc.http.HttpMethod;
import lombok.SneakyThrows;
import me.ultrapanda.Atelier;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.script.ScriptObject;
import me.ultrapanda.status.RequestType;
import me.ultrapanda.status.ResponseStatus;
import me.ultrapanda.status.UserStatus;
import me.ultrapanda.user.User;
import me.ultrapanda.utils.Crypto;
import me.ultrapanda.utils.LuaCipher;

import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static me.ultrapanda.Atelier.scriptLoader;

@Path
public class AtelierController {
    private final static SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private final static int staticKey = 812934;

    private final static Crypto crypto = new Crypto();
    private final static LuaCipher cipher = Atelier.luaCipher;

    private final AtelierDatabase atelierDatabase = Atelier.atelierDatabase;
    private final AtelierLogger logger = Atelier.atelierLogger;

    // http://localhost:5555/atelier?request=801&username=UltraPanda&password=1C94-E051-2930-88FB-36B4-7A5A-F1F1-4E6B&hwid=testhwid&script=lagsyncupdated&signature=d0e06723744f7f57bf4691550476a73b

    @Route(value = "/atelier", method = HttpMethod.GET)
    public void atelier(RouteContext ctx){
        try{
            String requestType = ctx.parameters().get("request").get(0);
            if(requestType == null || !(requestType.equals(RequestType.GET_LIST) || requestType.equals(RequestType.GET_LUA))){
                ctx.text(ResponseStatus.BAD_PARAMETERS);
                return;
            }

            if(ctx.parameters().size() < 5){
                ctx.text(ResponseStatus.BAD_PARAMETERS);
                return;
            }


            String username = ctx.parameters().get("username").get(0);
            String password = ctx.parameters().get("password").get(0);
            String hwid = ctx.parameters().get("hwid").get(0);
            String signature = ctx.parameters().get("signature").get(0);
            String time = ctx.parameters().get("time").get(0);
            String key = ctx.parameters().get("key").get(0);

            if(username == null || password == null || signature == null || time == null || key == null){
                ctx.text(ResponseStatus.BAD_REQUEST);
                return;
            }

            // 先验证签名 防止数据库操作造成不必要的性能损失.
            if(!validSignature(username, password, hwid, requestType, time, signature)){
                logger.warn(username + " 提供了一个非法签名. 正确签名: " + crypto.encryptMD5ToString(username + ":" + requestType + ":" + password + ":" + "SIGNATURE" + ":" + hwid + ":" + time));
                ctx.text(ResponseStatus.INVALID_SIGNATURE);
                return;
            }

            User user = atelierDatabase.getUserFromName(username);
            if(user == null){
                ctx.text(ResponseStatus.USER_UNKNOWN);
                return;
            }

            if(!user.getPassword().equals(password)){
                ctx.text(ResponseStatus.USER_WRONG_PASSWORD);
                return;
            }else if(!user.getHwid().equals(hwid)){
                if(hwid.length() != 32){
                    atelierDatabase.changeUserStatus(user.getUsername(), UserStatus.BANNED);
                    logger.warn("用户 " + user.getUsername() + " 提供了一个不合法的HWID，已经将它封禁. IP: " + ctx.address());
                    ctx.text(ResponseStatus.USER_BANNED);
                    return;
                }

                if(user.getHwid().equals("")){
                    atelierDatabase.setHwid(user.getUsername(), hwid);
                    logger.warn("用户 " + user.getUsername() + " 第一次登陆，HWID设置为了: " + hwid + " IP: " + ctx.address());
                }else{
                    logger.warn("用户 " + user.getUsername() + " 的当前HWID不匹配. 已拒绝请求. IP: " + ctx.address());
                    ctx.text(ResponseStatus.USER_WRONG_HWID);
                    return;
                }
            }else if(user.getUserStatus() == UserStatus.BANNED){
                logger.warn("用户 " + user.getUsername() + " 尝试登陆，但他已被封禁. IP: " + ctx.address());
                ctx.text(ResponseStatus.USER_BANNED);
                return;
            }

            // 用户已经完全验证
            if(!ctx.userAgent().startsWith("Valve/Steam HTTP Client 1.0") || !ctx.userAgent().contains("no")){
                ctx.text(ResponseStatus.USER_BANNED);
                atelierDatabase.changeUserStatus(user.getUsername(), UserStatus.BANNED);
                logger.warn("用户 " + user.getUsername() + " 的用户标识不正确，正在尝试破解，已封禁. (" + ctx.userAgent() + ")");

                return;
            }

            switch (requestType){
                default:
                    ctx.text(ResponseStatus.BAD_REQUEST);
                    break;
                case RequestType.GET_LIST:
                    StringBuilder stringBuilder = new StringBuilder(user.getRole() + "\n");

                    String nextLine = "";
                    for(ScriptObject scriptObject : scriptLoader.getScriptObjectsByName(user.getRole())){
                        stringBuilder.append(nextLine).append(scriptObject.getName());
                        nextLine = "\n";
                    }

                    logger.info("用户 " + user.getUsername() + " 登陆成功. [IP:" + ctx.address() + "] " + String.format("[%s]", format.format(new Date())));

                    ctx.text(cipher.encrypt(stringBuilder.toString(), staticKey, Integer.parseInt(key)));
                    break;
                case RequestType.GET_LUA:
                    if(ctx.parameters().get("script") == null){
                        ctx.text(ResponseStatus.BAD_PARAMETERS);
                        return;
                    }

                    String scriptName = ctx.parameters().get("script").get(0);
                    if(scriptName == null){
                        ctx.text(ResponseStatus.BAD_PARAMETERS);
                        return;
                    }

                    ScriptObject scriptObject = scriptLoader.getScriptObjectByName(user.getRole(), scriptName);

                    if(scriptObject == null) {
                        ctx.text(ResponseStatus.SCRIPT_UNKNOWN);
                        return;
                    }

                    ctx.text(cipher.encrypt(scriptObject.toBase64(), staticKey, Integer.parseInt(key)));
                    break;
            }
        }catch (NoSuchAlgorithmException noSuchAlgorithmException){
            logger.warn("出现无效算法错误.");
            noSuchAlgorithmException.printStackTrace();
        }catch (NullPointerException nullPointerException){
            logger.warn("出现空指针错误.");
            nullPointerException.printStackTrace();
        }catch (Exception exception){
            logger.warn("出现未预料的错误.");
            exception.printStackTrace();
        }
    }

    private boolean validSignature(String username, String password, String hwid, String requestType, String time, String signature) throws NoSuchAlgorithmException {
        return crypto.encryptMD5ToString(username + ":" + requestType + ":" + password + ":" + "SIGNATURE" + ":" + hwid + ":" + time).equals(signature);
    }

    @SneakyThrows
    @Route(value = "/version", method = HttpMethod.GET)
    public void version(RouteContext ctx){
        ctx.text(Atelier.VERSION);
    }
}
