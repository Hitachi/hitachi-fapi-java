package fapi.client.util;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.UUID;

public class CryptoUtil {

    /**
     * calcurate c_hash, s_hash, at_hash from input string
     */
    public static String calcurateXHash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            byte[] leftHalf = Arrays.copyOfRange(digest, 0, digest.length / 2);

            return Base64Url.encode(leftHalf);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String generateRandomUUID() {
        return UUID.randomUUID().toString();
    }
}
