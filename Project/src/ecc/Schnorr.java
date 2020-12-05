package ecc;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Random;

import ecc.EC;

public class Schnorr {
    public static class Signature {
        private ECPoint R;
        private BigInteger s;

        public ECPoint getR() {
            return R;
        }

        public BigInteger getS() {
            return s;
        }

        public void setR(ECPoint R) {
            this.R = R;
        }

        public void setS(BigInteger s) {
            this.s = s;
        }

        public Signature (ECPoint R, BigInteger s) {
            this.R = R;
            this.s = s;
        }

        public String toString() {
            return "R: " + EC.Points.printEPoint(R) + "\n" + "s: " + s.toString();
        }
    }
    public static Signature signGen (ECPoint publicKey, byte[] message, BigInteger privateKey) throws NoSuchAlgorithmException {
        //System.out.println("Signature generation...");
        byte r1[] = new byte[24];
        Random k = new SecureRandom();
        k.nextBytes(r1);

        BigInteger r = new BigInteger(r1);
        ECPoint R = EC.Points.scalmult(EC.Constants.G, r);

        BigInteger hash = new BigInteger(MessageHash.SHAsumInByteArray(message)).mod(EC.Constants.m);

        BigInteger sigS = EC.Modular.modMul(hash, privateKey);

        BigInteger sigS1 = EC.Modular.modAdd(r, sigS);

        //System.out.println(sigS1.toString(16));

        return new Signature(R, sigS1);
    }

    public static boolean signVerify (Signature signature, byte[] message, ECPoint publicKey) throws NoSuchAlgorithmException {
        //System.out.println("Signature verification...");
        ECPoint left = EC.Points.scalmult(EC.Constants.G, signature.getS());
        BigInteger hash = new BigInteger(MessageHash.SHAsumInByteArray(message)).mod(EC.Constants.m);
        ECPoint right = EC.Points.scalmult(publicKey, hash);
        right = EC.Points.addPoint(right, signature.getR());
        if (left.equals(right))
            return true;
        return false;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException{
        EC.KeyPair keyPair = new EC.KeyPair();

        //System.out.println(keyPair.getPrivateKey().toString(16));
        //System.out.println(EC.Points.printEPoint(keyPair.getPublicKey()));

        String message = "Hello";
        byte[] mess = message.getBytes();

        for (int i = 0; i <= 100; i++) {

            Signature signature = signGen(keyPair.getPublicKey(), mess, keyPair.getPrivateKey());
            System.out.println(signVerify(signature, mess, keyPair.getPublicKey()));
        }
    }
}
