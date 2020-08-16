package me.ultrapanda.console;

import me.ultrapanda.Atelier;
import me.ultrapanda.database.AtelierDatabase;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.role.Role;
import me.ultrapanda.status.UserStatus;
import me.ultrapanda.user.User;
import org.jline.reader.LineReader;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Terminal;

import java.io.File;
import java.io.FileWriter;

public class ConsoleThread extends Thread {
    private final String prompt;

    private final Terminal terminal;
    private final LineReader lineReader;

    private final AtelierLogger logger = Atelier.atelierLogger;
    private final AtelierDatabase database = Atelier.atelierDatabase;

    public ConsoleThread(String prompt, Terminal terminal, LineReader lineReader){
        this.prompt = prompt;
        this.terminal = terminal;
        this.lineReader = lineReader;

        logger.info("Atelier 控制台初始化成功.");
    }

    @Override
    public void run() {
        while(true){
            String lastCommand;
            String[] arg;

            try{
                lastCommand = lineReader.readLine(prompt);
                arg = lastCommand.split(" ");
            }catch (UserInterruptException uie) {
                logger.error("指令错误，输入 'help' 获取更多帮助.");
                return;
            }

            try{
                switch (arg[0].toLowerCase()) {
                    default:
                        logger.error("指令错误，输入 'help' 获取更多帮助.");
                        break;
                    case "help":
                        logger.info("帮助菜单: ");
                        logger.info("about - 获取本程序的相关信息.");
                        logger.info("exit - 安全退出 Atelier 服务.");
                        logger.info("refresh - 刷新 Lua脚本池.");
                        logger.info("-");
                        logger.info("createuser <用户名称> <用户组> - 创建用户");
                        logger.info("deleteuser <用户名称> - 删除用户");
                        logger.info("changerole <用户名称> <用户组> - 修改用户账户类型");
                        logger.info("setownedrole <用户名称> <用户组> - 修改用户管理权限所在的用户组");
                        logger.info("userinfo <用户名称> - 查看账户信息");
                        logger.info("resethwid <用户名称> - 重置账户HWID");
                        logger.info("exportcreds <用户名称> - 导出用户的证书文件");
                        logger.info("ban <用户名称> - 封禁用户");
                        logger.info("unban <用户名称> - 解封用户");
                        logger.info("-");
                        logger.info("createrole <用户组名称> - 创建用户组");
                        logger.info("deleterole <用户组名称> - 删除用户组");
                        logger.info("rolelist - 查看所有用户组");
                        break;
                    case "about":
                        logger.info("Atelier server made by UltraPanda with <3.");
                        break;
                    case "exit":
                        System.exit(0);
                        break;
                    case "createuser":
                        if(arg.length != 3 || arg[1] == null || arg[2] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.createUser(arg[1], arg[2]);
                        break;
                    case "userinfo":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        User user = database.getUserFromName(arg[1]);

                        if(user == null){
                            logger.error("用户不存在.");
                            break;
                        }

                        logger.info("用户名称: " + user.getUsername());
                        logger.info("用户密码: " + user.getPassword());
                        logger.info("用户HWID: " + (user.getHwid().isEmpty() ? "未设置" : user.getHwid()));
                        logger.info("用户类型: " + user.getRole().toUpperCase());
                        logger.info("用户管理权限所在用户组: " + (user.getOwnedRole().isEmpty() ? "未设置" : user.getOwnedRole().toUpperCase()));
                        logger.info("用户状态: " + user.getUserStatus().toString());

                        break;
                    case "deleteuser":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.deleteUser(arg[1]);
                        break;
                    case "changerole":
                        if(arg.length != 3 || arg[1] == null || arg[2] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.changeRole(arg[1], arg[2]);
                        break;
                    case "setownedrole":
                        if(arg.length != 3 || arg[1] == null || arg[2] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.setOwnedRole(arg[1], arg[2]);
                        break;
                    case "resethwid":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.resetHwid(arg[1]);
                        break;

                    case "ban":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        if(database.changeUserStatus(arg[1], UserStatus.BANNED)){
                            logger.info("成功封禁用户 " + arg[1]);
                        }else {
                            logger.error("用户不存在.");
                        }
                        break;
                    case "unban":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        if(database.changeUserStatus(arg[1], UserStatus.AVAILABLE)){
                            logger.info("成功解封用户 " + arg[1]);
                        }else {
                            logger.error("用户不存在.");
                        }
                        break;
                    case "exportcreds":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        User user1 = database.getUserFromName(arg[1]);

                        if(user1 == null){
                            logger.error("用户不存在.");
                            break;
                        }

                        File file = new File("exports" + File.separator + user1.getUsername() + File.separator + "VEL.creds");
                        File folder = new File("exports" + File.separator + user1.getUsername());
                        if(!file.exists()){
                            folder.mkdirs();
                            file.createNewFile();
                        }

                        FileWriter fileWriter = new FileWriter(file, false);
                        fileWriter.write(user1.getUsername());
                        fileWriter.write("\n");
                        fileWriter.write(user1.getPassword());

                        fileWriter.close();

                        logger.info("用户 " + user1.getUsername() + " 的证书文件已被导出到 " + file.getAbsolutePath());

                        break;
                    case "refresh":
                        Atelier.scriptLoader.refresh();
                        Atelier.configLoader.refresh();
                        Atelier.informationLoader.refresh();

                        break;
                    case "createrole":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.createRole(arg[1]);
                        break;
                    case "deleterole":
                        if(arg.length != 2 || arg[1] == null){
                            logger.error("指令用法错误，输入 'help' 获取更多帮助.");
                            break;
                        }

                        database.deleteRole(arg[1]);
                        break;
                    case "rolelist":
                        logger.info("当前 Roles: ");
                        for(Role role : database.getRoles()){
                            logger.info("- " + role.getRoleName());
                        }
                        break;
                }
            }catch (Exception exception){
                logger.error("发生了一个未预料的错误.");
                exception.printStackTrace();
            }
        }
    }
}
