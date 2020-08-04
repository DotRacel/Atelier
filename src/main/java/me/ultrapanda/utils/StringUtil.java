package me.ultrapanda.utils;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class StringUtil {

    public static String generateRandomKey(Crypto crypto) {
        try {
            UUID uuid = UUID.randomUUID();
            String original = crypto.hexToString(crypto.encryptMD5((uuid.toString() + System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8))).toUpperCase();
            String[] parts = new String[8];

            for(int i = 0 ; i < 8 ; i++){
                int start = Math.max(((i + 1) * 4 - 4), 0);
                parts[i] = original.substring(start, (i + 1) * 4);
            }

            return String.join("-", parts);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }


    /**
     * 将字节数组转为long<br>
     * 如果input为null,或offset指定的剩余数组长度不足8字节则抛出异常
     * @param input
     * @param offset 起始偏移量
     * @param littleEndian 输入数组是否小端模式
     * @return
     */
    public static long longFrom8Bytes(byte[] input, int offset, boolean littleEndian){
        long value=0;
        // 循环读取每个字节通过移位运算完成long的8个字节拼装
        for(int  count=0;count<8;++count){
            int shift=(littleEndian?count:(7-count))<<3;
            value |=((long)0xff<< shift) & ((long)input[offset+count] << shift);
        }
        return value;
    }
}
