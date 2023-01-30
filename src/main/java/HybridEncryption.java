import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class HybridEncryption {

    public static void main(String[] args) throws Exception {
        Alice alice = Alice.init();
        Bob bob = new Bob(alice.getPublicKey());
        HybridMessage hybridMessage = bob.encryptMessage();
        System.out.printf("Printing C.rsa: %s\n", hybridMessage.getcRSA());
        System.out.printf("First 32 bytes of C.aes: %s\n", hybridMessage.getcAES().substring(0, 32));
        String m = alice.decryptHybridMessage(hybridMessage);
        System.out.printf("Decrypted first 32 bytes of M: %s\n", m.substring(0, 32));
    }
}

class HybridMessage {
    private final BigInteger cRSA;
    private final String cAES;

    public HybridMessage(BigInteger cRSA, String cAES) {
        this.cRSA = cRSA;
        this.cAES = cAES;
    }

    public BigInteger getcRSA() {
        return cRSA;
    }

    public String getcAES() {
        return cAES;
    }
}

class PublicKey {
    private final BigInteger e;
    private final BigInteger n;

    public PublicKey(BigInteger e, BigInteger n) {
        this.e = e;
        this.n = n;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getN() {
        return n;
    }

    @Override
    public String toString() {
        return String.format("(%s, %s)", e, n);
    }
}

class PrivateKey {
    private final BigInteger d;
    private final BigInteger p;
    private final BigInteger q;

    public PrivateKey(BigInteger d, BigInteger p, BigInteger q) {
        this.d = d;
        this.p = p;
        this.q = q;
    }

    public BigInteger getD() {
        return d;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    @Override
    public String toString() {
        return String.format("(%s, %s, %s)", d, p, q);
    }
}

class Alice {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final Alice alice = new Alice();

    private Alice() {
    }

    public static Alice init() {
        BigInteger p = new BigInteger("19211916981990472618936322908621863986876987146317321175477459636156953561475008733870517275438245830106443145241548501528064000686696553079813968930084003413592173929258239545538559059522893001415540383237712787805857248668921475503029012210091798624401493551321836739170290569343885146402734119714622761918874473987849224658821203492683692059569546468953937059529709368583742816455260753650612502430591087268113652659115398868234585603351162620007030560547611");
        BigInteger q = new BigInteger("49400957163547757452528775346560420645353827504469813702447095057241998403355821905395551250978714023163401985077729384422721713135644084394023796644398582673187943364713315617271802772949577464712104737208148338528834981720321532125957782517699692081175107563795482281654333294693930543491780359799856300841301804870312412567636723373557700882499622073341225199446003974972311496703259471182056856143760293363135470539860065760306974196552067736902898897585691");

        BigInteger phiOfn = p.subtract(BigInteger.ONE).multiply((q.subtract(BigInteger.ONE)));
        BigInteger e = generateRandomE(phiOfn);
        BigInteger d = e.modInverse(phiOfn);

        alice.privateKey = new PrivateKey(d, p, q);
        alice.publicKey = new PublicKey(e, p.multiply(q));

        return alice;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String decryptHybridMessage(HybridMessage hybridMessage)
            throws Exception {
        BigInteger n = this.privateKey.getP().multiply(this.privateKey.getQ());
        BigInteger decryptedSecret = getSignCorrectedValue(
                decryptRSA(hybridMessage.getcRSA(), this.privateKey.getD(), n)
        );
        SecretKey decryptedSecretKey = new SecretKeySpec(getSignCorrectedValue(decryptedSecret).toByteArray(), "AES");
        System.out.printf("Decrypted key K: %s\n", decryptedSecret.toString(16));

        return decryptAES(hybridMessage.getcAES(), decryptedSecretKey);
    }

    private static BigInteger generateRandomE(BigInteger phiOfn) {
        BigInteger e = new BigInteger(phiOfn.bitLength(), new Random());
        while (!phiOfn.gcd(e).equals(BigInteger.ONE)) {
            e = new BigInteger(phiOfn.bitLength(), new Random());
        }
        return e;
    }

    public static String decryptAES(String cipherText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static BigInteger decryptRSA(BigInteger c, BigInteger d, BigInteger n) {
        return c.modPow(d, n);
    }

    private static BigInteger getSignCorrectedValue(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0 && bytes[1] < 0) {
            return new BigInteger(Arrays.copyOfRange(bytes, 1, bytes.length));
        }
        return value;
    }
}

class Bob {

    private final PublicKey alicePublicKey;

    public Bob(PublicKey alicePublicKey) {
        this.alicePublicKey = alicePublicKey;
    }

    public HybridMessage encryptMessage()
            throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.printf("\nThe AES key in hex K: %s\n", new BigInteger(secretKey.getEncoded()).toString(16));

        char[] chars = new char[1024 * 1024];
        Arrays.fill(chars, 't');
        String m = new String(chars);

        System.out.printf("The first 32 bytes of M: %s\n", m.substring(0, 32));
        BigInteger aesSecret = new BigInteger(1, secretKey.getEncoded());
        return new HybridMessage(encryptRSA(aesSecret, alicePublicKey.getE(), alicePublicKey.getN()),
                encryptAES(m, secretKey));
    }

    public static BigInteger encryptRSA(BigInteger m, BigInteger e, BigInteger n) {
        return m.modPow(e, n);
    }

    public static String encryptAES(String input, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }
}
