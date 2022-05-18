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
     public static final String PASSWORD_KEY = "FCUyZ3PcYJGJFVuAguHcV3mTbYg=";
    /**
     * Computes RFC 2104-compliant HMAC signature.
     * * @param data
     * The data to be signed.
     *
     * @param key The signing key.
     * @return The Base64-encoded RFC 2104-compliant HMAC signature.
     * @throws SignatureException when signature generation fails
     */

    public static String calculateRFC2104HMAC(String data) {
        String result = null;
        try {

            SecretKeySpec signingKey = new SecretKeySpec(PASSWORD_KEY.getBytes(), SHA1_ALGORITHM);

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
