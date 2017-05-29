package algorithms;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Encrypt {
    public static String digestSHA(String pwd) {
        // TODO Auto-generated method stub
        byte[] hash = null;
        try {
            hash = MessageDigest.getInstance("sha").digest(pwd.getBytes());
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < hash.length; i++) {
            if ((0xff & hash[i]) < 0x10) {
                hexString.append("0"
                        + Integer.toHexString((0xFF & hash[i])));
            } else {
                hexString.append(Integer.toHexString(0xFF & hash[i]));
            }
        }

        return hexString.toString();
    }
}
