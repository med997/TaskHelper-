import org.apache.commons.codec.binary.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

//import java.util.logging.Level;
//import org.apache.log4j.Logger;

public class EncryptionData {

    private static final String SHA1_ALGORITHM = "HmacSHA1";
    public static String getSHAHash(String givenText) {
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(givenText.getBytes());

        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            //logger.error(ex);
        }
        byte byteData[] = md.digest();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();

    }

    /**
     * Computes RFC 2104-compliant HMAC signature.
     * * @param data
     * The data to be signed.
     *
     * @param key The signing key.
     * @return The Base64-encoded RFC 2104-compliant HMAC signature.
     * @throws SignatureException when signature generation fails
     */

    public static String calculateRFC2104HMAC(String data, String key) {
        String result = null;
        try {

            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), SHA1_ALGORITHM);

            Mac mac = Mac.getInstance(SHA1_ALGORITHM);
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(data.getBytes());
            result = new String(Base64.encodeBase64(rawHmac, false));
        } catch (Exception e) {
            //logger.error(e);
            e.printStackTrace();
        }
        return result;
    }
}
