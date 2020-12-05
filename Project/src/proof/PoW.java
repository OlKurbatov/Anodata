package proof;

import ecc.MessageHash;

import java.security.NoSuchAlgorithmException;

public class PoW {
    public static String PoWGen (String message) throws NoSuchAlgorithmException {
        int i = 0;
        while(true) {
            if (MessageHash.SHAsumInByteArray((message + i).getBytes())[0] == 0 && MessageHash.SHAsumInByteArray((message + i).getBytes())[1] == 0 &&
                    MessageHash.SHAsumInByteArray((message + i).getBytes())[2] == 0){
                return Integer.toString(i, 10);
            }
            i++;
        }
    }

    public static boolean PoWVer (String nonce, String message) throws NoSuchAlgorithmException{
        if (MessageHash.SHAsumInByteArray((message + nonce).getBytes())[0] == 0 && MessageHash.SHAsumInByteArray((message + nonce).getBytes())[1] == 0 &&
                MessageHash.SHAsumInByteArray((message + nonce).getBytes())[2] == 0)
        {
            return true;
        }
        else
            return false;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String nonce = PoWGen("Hello");
        System.out.println(nonce);
        System.out.println(PoWVer(nonce, "Hello"));
    }
}
