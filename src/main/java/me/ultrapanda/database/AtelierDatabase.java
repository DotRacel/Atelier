package me.ultrapanda.database;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import me.ultrapanda.Atelier;
import me.ultrapanda.logger.AtelierLogger;
import me.ultrapanda.role.Role;
import me.ultrapanda.status.UserStatus;
import me.ultrapanda.user.User;
import me.ultrapanda.utils.Crypto;
import me.ultrapanda.utils.StringUtil;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;

import java.util.ArrayList;
import java.util.List;

import static com.mongodb.client.model.Updates.combine;
import static com.mongodb.client.model.Updates.set;

public class AtelierDatabase {
    private final MongoClient mongoClient;
    private final String databaseName;

    private MongoDatabase mongoDatabase;

    private static final AtelierLogger logger = Atelier.atelierLogger;
    private static final Crypto crypto = new Crypto();

    public List<Role> cachedRoles = new ArrayList<>();

    public AtelierDatabase(String address, int port, String databaseName) {
        this.mongoClient = new MongoClient(address, port);
        this.databaseName = databaseName;
    }

    public void connect(){
        try{
            CodecRegistry codecRegistry = CodecRegistries.fromRegistries(
                    MongoClientSettings.getDefaultCodecRegistry(),
                    CodecRegistries.fromProviders(PojoCodecProvider.builder().automatic(true).build())
            );

            mongoDatabase = mongoClient.getDatabase(databaseName).withCodecRegistry(codecRegistry);
            logger.info("Atelier 数据库连接成功.");
        }catch (Exception exception){
            logger.error("无法连接至数据库.");
            exception.printStackTrace();
            System.exit(-1);
        }
    }

    public MongoCollection<User> getUserCollection(){
        String name = "users";
        Class<User> clazz = User.class;

        for(String names : mongoDatabase.listCollectionNames()){
            if(names.equals(name)){
                return mongoDatabase.getCollection(name, clazz);
            }
        }

        // The collection is not exist, so we create a new one and return.
        mongoDatabase.createCollection(name);
        return mongoDatabase.getCollection(name, clazz);
    }

    public MongoCollection<Role> getRoleCollection(){
        String name = "roles";
        Class<Role> clazz = Role.class;

        for(String names : mongoDatabase.listCollectionNames()){
            if(names.equals(name)){
                return mongoDatabase.getCollection(name, clazz);
            }
        }

        // The collection is not exist, so we create a new one and return.
        mongoDatabase.createCollection(name);
        return mongoDatabase.getCollection(name, clazz);
    }

    public void createRole(String name){
        if(getRoleCollection().find(Filters.eq("roleName", name)).first() == null){
            Role role = new Role(name);
            getRoleCollection().insertOne(role);

            logger.info("成功创建用户组 " + name + ".");
            refreshRoleCache();
        }
    }

    public void deleteRole(String name){
        if(getRoleCollection().deleteOne(Filters.eq("roleName", name)).getDeletedCount() != 0){
            logger.info("成功删除用户组 " + name + ".");

            refreshRoleCache();
        }else {
            logger.info("用户组 " + name + " 不存在.");
        }
    }

    public List<Role> getRoles(){
        List<Role> list = new ArrayList<>();
        getRoleCollection().find().forEach(list::add);

        return list;
    }

    public boolean isValidRole(String name){
        for(Role role : cachedRoles){
            if(role.getRoleName().equalsIgnoreCase(name)) return true;
        }

        return false;
    }

    public void refreshRoleCache(){
        this.cachedRoles.clear();
        this.cachedRoles.addAll(getRoles());
    }

    public void createUser(User user){
        if(getUserFromName(user.getUsername()) != null) {
            logger.error("用户 " + user.getUsername() + " 已存在，无法创建.");
            return;
        }

        getUserCollection().insertOne(user);
        logger.info("成功创建用户 " + user.getUsername() + "(" + user.getPassword() + ")");
    }

    public void createUser(String username, String role){
        if(isValidRole(role)){
            User user = new User(username, StringUtil.generateRandomKey(crypto), role.toLowerCase(), "", UserStatus.AVAILABLE, "");
            createUser(user);
        }else{
            logger.error("所提供的用户组名称不正确.");
        }
    }

    public void deleteUser(String username){
        User user = getUserFromName(username);

        if(user == null){
            logger.error("用户 " + username + " 不存在.");
            return;
        }

        if(getUserCollection().deleteOne(Filters.eq("username", username)).getDeletedCount() != 0) {
            logger.info("成功删除用户 " + username + ".");
        }else {
            logger.error("用户 " + username + " 不存在.");
        }
    }

    public void changeRole(String username, String role){
        if(isValidRole(role)){
            if(getUserCollection().updateOne(Filters.eq("username", username), combine(set("role", role))).getModifiedCount() != 0){
                logger.info("成功将用户 " + username + " 的账户类型修改为了 " + role.toUpperCase() + ".");
            }else {
                logger.warn("用户 " + username + "不存在.");
            }
        }else {
            logger.error("提供了一个错误的用户组名称.");
        }
    }

    public void setOwnedRole(String username, String role){
        if(isValidRole(role)){
            if(getUserCollection().updateOne(Filters.eq("username", username), combine(set("ownedRole", role))).getModifiedCount() != 0){
                logger.info("成功将用户 " + username + " 的管理权限所在用户组修改为了 " + role.toUpperCase() + ".");
            }else {
                logger.warn("用户 " + username + "不存在.");
            }
        }else {
            logger.error("提供了一个错误的用户组名称.");
        }
    }

    public void resetHwid(String username){
        if(getUserCollection().updateOne(Filters.eq("username", username), combine(set("hwid", ""))).getModifiedCount() != 0){
            logger.info("成功将用户 " + username + " 的 HWID重置.");
        }else {
            logger.warn("用户 " + username + "不存在.");
        }
    }

    public boolean setHwid(String username, String hwid){
        return getUserCollection().updateOne(Filters.eq("username", username), combine(set("hwid", hwid))).getModifiedCount() != 0;
    }

    public boolean changeUserStatus(String username, UserStatus userStatus){
        return getUserCollection().updateOne(Filters.eq("username", username), combine(set("userStatus", userStatus.toString().toUpperCase()))).getModifiedCount() != 0;
    }

    public User getUserFromName(String username){
        return getUserCollection().find(Filters.eq("username", username)).first();
    }
}
