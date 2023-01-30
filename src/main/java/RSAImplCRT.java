import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;

public class RSAImplCRT {

    private long totalDuration, totalDurationCrt, durationCp, durationCq, durationMp, durationMq;

    public static void main(String[] args) {
        RSAImplCRT rsaImplCRT = new RSAImplCRT();
        BigInteger p = new BigInteger("19211916981990472618936322908621863986876987146317321175477459636156953561475008733870517275438245830106443145241548501528064000686696553079813968930084003413592173929258239545538559059522893001415540383237712787805857248668921475503029012210091798624401493551321836739170290569343885146402734119714622761918874473987849224658821203492683692059569546468953937059529709368583742816455260753650612502430591087268113652659115398868234585603351162620007030560547611");
        BigInteger q = new BigInteger("49400957163547757452528775346560420645353827504469813702447095057241998403355821905395551250978714023163401985077729384422721713135644084394023796644398582673187943364713315617271802772949577464712104737208148338528834981720321532125957782517699692081175107563795482281654333294693930543491780359799856300841301804870312412567636723373557700882499622073341225199446003974972311496703259471182056856143760293363135470539860065760306974196552067736902898897585691");
        BigInteger n = p.multiply(q);

        BigInteger phiOfn = p.subtract(BigInteger.ONE).multiply((q.subtract(BigInteger.ONE)));
        BigInteger e = rsaImplCRT.generateRandomE(phiOfn);
        BigInteger d = e.modInverse(phiOfn);

        //encryption
        BigInteger m = new BigInteger(phiOfn.bitLength() - 1, new Random());
        BigInteger c = rsaImplCRT.encryptMessage(m, e, n);

        System.out.printf("\nChosen message is m = %s\n", m);
        System.out.printf("Ciphertext is c = %s\n", c);

        //decryption - tracking execution time in nanoseconds
        BigInteger mNorm = rsaImplCRT.decryptCipher(c, d, n);
        BigInteger mCrt = rsaImplCRT.decryptCipherUsingCRT(c, d, p, q, n);

        System.out.printf("Decrypted message m = %s\n", mCrt);

        System.out.printf("Computation time of c ^ d mod n is %d ns (in nanoseconds)\n", rsaImplCRT.totalDuration);
        System.out.printf("Computation time of the CRT-based RSA decryption is %d ns (cP = %d ns, cQ = %d ns, mP = %d ns, mQ = %d ns)\n", rsaImplCRT.totalDurationCrt, rsaImplCRT.durationCp, rsaImplCRT.durationCq, rsaImplCRT.durationMp, rsaImplCRT.durationMq);

        System.out.printf("CRT based RSA decryption correctness verification status: %s\n", (mCrt.compareTo(mNorm) == 0 ? "SUCCESS" : "FAILURE"));

        System.out.println("----------------------------");
    }

    public BigInteger encryptMessage(BigInteger m, BigInteger e, BigInteger n) {
        return m.modPow(e, n);
    }

    public BigInteger decryptCipher(BigInteger c, BigInteger d, BigInteger n) {
        Instant start = Instant.now();
        BigInteger mDash = c.modPow(d, n);
        totalDuration = Duration.between(start, Instant.now()).toNanos();
        return mDash;
    }

    public BigInteger decryptCipherUsingCRT(BigInteger c, BigInteger d, BigInteger p, BigInteger q, BigInteger n) {
        Instant current = Instant.now();
        Instant start = current;

        BigInteger cP = c.mod(p);
        durationCp = Duration.between(current, Instant.now()).toNanos();
        current = Instant.now();
        BigInteger cQ = c.mod(q);
        durationCq = Duration.between(current, Instant.now()).toNanos();


        BigInteger dP = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dQ = d.mod(q.subtract(BigInteger.ONE));
        current = Instant.now();
        BigInteger mP = cP.modPow(dP, p);
        durationMp = Duration.between(current, Instant.now()).toNanos();
        current = Instant.now();
        BigInteger mQ = cQ.modPow(dQ, q);
        durationMq = Duration.between(current, Instant.now()).toNanos();
        System.out.printf("mP = %s\nmQ = %s\n", mP, mQ);

        BigInteger qDash = q.modInverse(p);
        BigInteger pDash = p.modInverse(q);
        BigInteger mDash = mP.multiply(q).multiply(qDash).add(mQ.multiply(p).multiply(pDash)).mod(n);
        totalDurationCrt = Duration.between(start, Instant.now()).toNanos();
        return mDash;
    }

    private BigInteger generateRandomE(BigInteger phiOfn) {
        BigInteger e = new BigInteger(phiOfn.bitLength(), new Random());
        while (!phiOfn.gcd(e).equals(BigInteger.ONE)) {
            e = new BigInteger(phiOfn.bitLength(), new Random());
        }
        return e;
    }
}