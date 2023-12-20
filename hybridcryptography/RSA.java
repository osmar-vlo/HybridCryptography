package hybridcryptography;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private BigInteger n;
    private BigInteger d;
    private BigInteger e;
    
    private int bitlen = 2048;

    public RSA() {
    }

    public RSA(BigInteger d, BigInteger e, BigInteger n) {
        this.d = d;
        this.e = e;
        this.n = n;
    }

    public void generarRSA() {
        SecureRandom random = new SecureRandom();
        BigInteger p = generatePrimeNumber(bitlen, random);
        BigInteger q = generatePrimeNumber(bitlen, random);
        n = p.multiply(q);

        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        do {
            this.e = generatePrimeNumber(bitlen, random);
        } while (this.e.compareTo(BigInteger.ONE) <= 0 || this.e.compareTo(m) >= 0 || !this.e.gcd(m).equals(BigInteger.ONE));

        this.d = this.e.modInverse(m);
    }

    private BigInteger generatePrimeNumber(int bitLength, SecureRandom random) {
        BigInteger prime;
        do {
            prime = BigInteger.probablePrime(bitLength, random);
        } while (!isPrime(prime));
        return prime;
    }

    private boolean isPrime(BigInteger number) {
        int certainty = 100;
        return number.isProbablePrime(certainty);
    }

    public synchronized String cifrar(String message, String keypublic, String modulo) {
        BigInteger e = new BigInteger(keypublic);
        BigInteger n = new BigInteger(modulo);
        byte[] bytes = message.getBytes();
        BigInteger plaintext = new BigInteger(bytes);
        BigInteger ciphertext = plaintext.modPow(e, n);
        return ciphertext.toString();
    }

    public synchronized String descifrar(String message, BigInteger d, String modulo) {
        BigInteger ciphertext = new BigInteger(message);
        BigInteger n = new BigInteger(modulo);
        BigInteger plaintext = ciphertext.modPow(d, n);
        byte[] plaintextBytes = plaintext.toByteArray();
        String plaintextString;
        try {
            plaintextString = new String(plaintextBytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            plaintextString = "";
        }
        return plaintextString;
    }

    synchronized BigInteger getPublicKey() {
        return e;
    }

    synchronized BigInteger getPrivateKey() {
        return d;
    }

    synchronized BigInteger getModulus() {
        return n;
    }
}
