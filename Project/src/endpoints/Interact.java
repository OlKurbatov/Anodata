package endpoints;

import ecc.EC;
import ecc.ECDH;
import ecc.Stealth;
import encr.AES;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Random;

public class Interact {

    public static EC.KeyPair keyPairGeneration (){
        return new EC.KeyPair();
    }

    public static String encryptMessage (String message, BigInteger ownPrivateKey, ECPoint receiverPublicKey){
        ECPoint commonSecret = ECDH.formSecret(ownPrivateKey, receiverPublicKey);
        String cypherText = AES.encrypt(message, EC.Points.printEPoint(commonSecret));
        return cypherText;
    }

    public static String decryptMessage (String message, BigInteger ownPrivateKey, ECPoint senderPublicKey){
        ECPoint commonSecret = ECDH.formSecret(ownPrivateKey, senderPublicKey);
        String plainText = AES.decrypt(message, EC.Points.printEPoint(commonSecret));
        return plainText;
    }

    public static Stealth generateOneTimeValue (ECPoint receiverPublicKey) throws NoSuchAlgorithmException {

        byte r1[] = new byte[24];
        Random k = new SecureRandom();
        k.nextBytes(r1);
        BigInteger r = new BigInteger(r1);
        Stealth oneTimeValue = Stealth.ContainerIdFormation(r, receiverPublicKey);
        return oneTimeValue;
    }

    public static boolean verifyOneTimeValue (BigInteger ownPrivateKey, Stealth stealth) throws NoSuchAlgorithmException {
        return Stealth.ContainerIdVerification(ownPrivateKey, stealth);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        EC.KeyPair keyPairAlice = new EC.KeyPair();
        EC.KeyPair keyPairBob = new EC.KeyPair();

        String cypherText = encryptMessage("Hello!", keyPairAlice.getPrivateKey(), keyPairBob.getPublicKey());
        String plainText = decryptMessage(cypherText, keyPairBob.getPrivateKey(), keyPairAlice.getPublicKey());

        System.out.println(cypherText);
        System.out.println(plainText);

        Stealth bobOneTimeValue = generateOneTimeValue(keyPairBob.getPublicKey());
        System.out.println(verifyOneTimeValue(keyPairBob.getPrivateKey(), bobOneTimeValue));
    }
}