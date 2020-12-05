package ecc;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import ecc.EC.KeyPair;

public class ECDH {

    public static ECPoint formSecret(BigInteger ownPrivateKey, ECPoint counterPublicKey){
        return EC.Points.scalmult(counterPublicKey, ownPrivateKey);
    }
}
