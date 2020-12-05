package proof;

import ecc.MessageHash;

import java.security.NoSuchAlgorithmException;

public class PoW {
    public static int PoWGen (String message) throws NoSuchAlgorithmException {
        int i = 0;
        while(true) {
            if (MessageHash.SHAsumInByteArray((message + i).getBytes())[0] == 0 && MessageHash.SHAsumInByteArray((message + i).getBytes())[1] == 0 &&
                    MessageHash.SHAsumInByteArray((message + i).getBytes())[2] == 0){
                return i;
            }
            i++;
        }
    }

    public static boolean PoWVer (int i, String message) throws NoSuchAlgorithmException{
        if (MessageHash.SHAsumInByteArray((message + i).getBytes())[0] == 0 && MessageHash.SHAsumInByteArray((message + i).getBytes())[1] == 0 &&
                MessageHash.SHAsumInByteArray((message + i).getBytes())[2] == 0)
        {
            return true;
        }
        else
            return false;
    }
}
