
import java.math.BigInteger;

public class Main {

    public static void main(String[] args) {
        Main rsa = new Main();
        
        int p = 3;
        int q = 11;
        int e = 3;
        int n = p * q;

        int m = 4;
        int s = 10;

        // Check public key
        System.out.println("Public key: "
                + rsa.checkPublicKey(p, q, e));

        // Calculate private key
        int d = rsa.calculatePrivateKey(p, q, e);
        System.out.println("Private key: " + d);

        // Encrypt and decrypt
        int encrypted = rsa.encryptMessage(m, e, n);
        int decrypted = rsa.decryptMessage(encrypted, d, n);

        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        // Create and validate signature
        int signature = rsa.createSignature(m, d, n, s);
        int valid = rsa.validateSignature(signature, m, e, n, s);

        System.out.println("Hash: " + (m % s));
        System.out.println("Signature: " + signature);
        System.out.println("Signature valid: " + valid);
    }

    public boolean checkPrimes(int p, int q) {
        return p != q
                && BigInteger.valueOf(p).isProbablePrime(100)
                && BigInteger.valueOf(q).isProbablePrime(100);
    }

    public long calculatePhi(int p, int q) {
        return ((long) p - 1) * (q - 1);
    }

    public int checkPublicKey(int p, int q, int e) {
        if (!checkPrimes(p, q)) {
            return 0;
        }

        long phi = calculatePhi(p, q);

        if (e > 1 && e < phi) {
            BigInteger valueE = BigInteger.valueOf(e);
            BigInteger valuePHI = BigInteger.valueOf(phi);

            if (valueE.gcd(valuePHI).equals(BigInteger.ONE)) {
                return 1;
            }
        }

        return 0;
    }

    public int calculatePrivateKey(int p, int q, int e) {
        if (checkPublicKey(p, q, e) == 0) {
            return -1;
        }

        long phi = calculatePhi(p, q);

        BigInteger valueE = BigInteger.valueOf(e);
        BigInteger valuePHI = BigInteger.valueOf(phi);

        int d = valueE.modInverse(valuePHI).intValueExact();

        return d;
    }

    public int encryptMessage(int m, int k, int n) {
        BigInteger message = BigInteger.valueOf(m);
        BigInteger key = BigInteger.valueOf(k);
        BigInteger modulus = BigInteger.valueOf(n);

        return message.modPow(key, modulus).intValueExact();
    }

    public int decryptMessage(int c, int k, int n) {
        BigInteger encrypted = BigInteger.valueOf(c);
        BigInteger key = BigInteger.valueOf(k);
        BigInteger modulus = BigInteger.valueOf(n);

        return encrypted.modPow(key, modulus).intValueExact();
    }

    public int createSignature(int m, int k, int n, int s) {
        int hash = m % s;
        return encryptMessage(hash, k, n);

    }

    public int validateSignature(int signature, int m, int k, int n, int s) {
        int hash = m % s;
        int verifiedHash = decryptMessage(signature, k, n);

        if (hash == verifiedHash) {
            return 1;
        }

        return 0;

    }
}
