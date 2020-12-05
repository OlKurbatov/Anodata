package ecc;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;

public class Stealth {

    private String oneTimeValue;
    private ECPoint R;

    public void setR(ECPoint r) {
        R = r;
    }

    public void setOneTimeValue(String oneTimeValue) {
        this.oneTimeValue = oneTimeValue;
    }

    public ECPoint getR() {
        return R;
    }

    public String getOneTimeValue() {
        return oneTimeValue;
    }

    public static Stealth ContainerIdFormation(BigInteger secret, ECPoint receiverPK) throws NoSuchAlgorithmException {
        Stealth stealth = new Stealth();
        ECPoint point = EC.Points.scalmult(receiverPK, secret);

        stealth.setOneTimeValue(MessageHash.SHAsumInString(EC.Points.printEPoint(point).getBytes()));
        stealth.setR(EC.Points.scalmult(EC.Constants.G, secret));

        return stealth;
    }

    public static boolean ContainerIdVerification(BigInteger secret, Stealth stealth) throws NoSuchAlgorithmException {
        ECPoint point = EC.Points.scalmult(stealth.getR(), secret);
        if (MessageHash.SHAsumInString(EC.Points.printEPoint(point).getBytes()).equalsIgnoreCase(stealth.getOneTimeValue()))
            return true;
        else
            return false;
    }
}
