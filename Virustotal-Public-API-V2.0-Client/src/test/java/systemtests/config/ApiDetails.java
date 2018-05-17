package systemtests.config;

public class ApiDetails {
    static final String[] API_KEYS = new String[] {
            "1cffb63fb97039e4cc389aca6bd4a3c72a0a7ec9849e4b3e4bd98fefe8d624af",
            "3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8"
    };

    ApiDetails instance;
    private static int curr = 0;

    public static String API_KEY() {
        String r = API_KEYS[curr];
        curr = (curr + 1)%API_KEYS.length;
        return r;
    }
}
