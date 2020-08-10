package me.ultrapanda.status;

public class ResponseStatus {
    public final static String BAD_PARAMETERS = "400";
    public final static String BAD_REQUEST = "401";
    public final static String INVALID_SIGNATURE = "402";
    public final static String INTERNAL_ERROR = "403";

    public final static String USER_UNKNOWN = "500";
    public final static String USER_WRONG_PASSWORD = "501";
    public final static String USER_WRONG_HWID = "502";
    public final static String USER_BANNED = "503";
    public final static String REQUEST_NOT_ALLOWED = "504";

    public final static String SCRIPT_UNKNOWN = "600";
    public final static String CONFIG_UNKNOWN = "601";

    public final static String REQUEST_RECEIVED = "700";
}
