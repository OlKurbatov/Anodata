package ecc;

import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

public class MessageHash {
    public static String SHAsumInString(byte[] convertme) throws NoSuchAlgorithmException {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        return byteArray2Hex(md.digest(convertme));
    }

    public static byte[] SHAsumInByteArray(byte[] convertme) throws NoSuchAlgorithmException {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        return md.digest(convertme);
    }

    public static String byteArray2Hex(byte[] hash) {
        Formatter formatter = new Formatter();
        try{
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }finally {
            formatter.close();
        }
    }
}
