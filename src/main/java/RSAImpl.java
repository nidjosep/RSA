import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.Random;
import java.util.Scanner;

public class RSAImpl {
    public static void main(String[] args) {
        BigInteger p = new BigInteger("19211916981990472618936322908621863986876987146317321175477459636156953561475008733870517275438245830106443145241548501528064000686696553079813968930084003413592173929258239545538559059522893001415540383237712787805857248668921475503029012210091798624401493551321836739170290569343885146402734119714622761918874473987849224658821203492683692059569546468953937059529709368583742816455260753650612502430591087268113652659115398868234585603351162620007030560547611");
        BigInteger q = new BigInteger("49400957163547757452528775346560420645353827504469813702447095057241998403355821905395551250978714023163401985077729384422721713135644084394023796644398582673187943364713315617271802772949577464712104737208148338528834981720321532125957782517699692081175107563795482281654333294693930543491780359799856300841301804870312412567636723373557700882499622073341225199446003974972311496703259471182056856143760293363135470539860065760306974196552067736902898897585691");
        BigInteger n = p.multiply(q);

        BigInteger phiOfn = p.subtract(BigInteger.ONE).multiply((q.subtract(BigInteger.ONE)));
        BigInteger e = generateRandomE(phiOfn);
        BigInteger d = e.modInverse(phiOfn);

        System.out.printf("\nThe first prime is p = %s\t\n", p);
        System.out.printf("The second prime is q = %s\t\n", q);
        System.out.printf("The composite modulus n = %s\t\n", n);
        System.out.printf("The encryption exponent e = %s\t\n", e);
        System.out.printf("The decryption exponent d = %s\t\n", d);

        int option = getUserOption();
        System.out.printf("User has chosen the option : %d\n---------------------\n", option);

        //encryption
        BigInteger m = new BigInteger(phiOfn.bitLength() - 1, new Random());
        System.out.println("Encryption:");
        BigInteger c = encryptMessage(m, e, n);

        System.out.printf("Plaintext (randomly generate) to be encrypted is m = %s\n", m);
        System.out.printf("Ciphertext is c = %s\n---------------------\n", c);

        if (option == 2) {
            //decryption
            System.out.println("Decryption:");
            BigInteger mDash = decryptCipher(c, d, n);
            System.out.printf("Ciphertext to be decrypted is c = %s\n", c);
            System.out.printf("Decrypted plaintext is m = %s\n---------------------\n", mDash);
            System.out.printf("RSA implementation correctness verification status: %s\n---------------------\n", (mDash.compareTo(m) == 0 ? "SUCCESS" : "FAILURE"));
        }
    }

    private static int getUserOption() {
        int option = 0;
        System.out.print("---------------------\nPlease enter an option:\n 1 to Encrypt\n 2 to Decrypt\n Your Option: ");
        Scanner scanner = new Scanner(System.in);
        while (true) {
            try {
                option = scanner.nextInt();
            } catch (Exception ex) {
                System.out.print("Invalid input. ");
            }
            if (option == 1 || option == 2) {
                break;
            }
            scanner.nextLine();
            System.out.print("Please enter either 1 or 2: ");
        }
        scanner.close();
        return option;
    }

    public static BigInteger encryptMessage(BigInteger m, BigInteger e, BigInteger n) {
        Instant start = Instant.now();
        BigInteger c = m.modPow(e, n);
        Instant end = Instant.now();
        System.out.printf("Encryption done in %s ms\n", Duration.between(start, end).toMillis());
        return c;
    }

    public static BigInteger decryptCipher(BigInteger c, BigInteger d, BigInteger n) {
        Instant start = Instant.now();
        BigInteger mDash = c.modPow(d, n);
        Instant end = Instant.now();
        System.out.printf("Decryption done in %s ms\n", Duration.between(start, end).toMillis());
        return mDash;
    }

    private static BigInteger generateRandomE(BigInteger phiOfn) {
        BigInteger e = new BigInteger(phiOfn.bitLength(), new Random());
        while (!phiOfn.gcd(e).equals(BigInteger.ONE)) {
            e = new BigInteger(phiOfn.bitLength(), new Random());
        }
        return e;
    }
}

