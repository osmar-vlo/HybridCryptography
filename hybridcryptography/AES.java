package hybridcryptography;

import java.nio.charset.StandardCharsets;
import javax.crypto.*; 
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

public class AES {
    
    public static String generarClaveAES() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey clave = keyGenerator.generateKey();
        byte[] claveBytes = clave.getEncoded();
        return Base64.getEncoder().encodeToString(claveBytes);
    }

    public static String generarIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    public static String cifrarAES(String texto, String claveString, String ivString) throws Exception {
        byte[] contenidoArchivo = texto.getBytes(StandardCharsets.UTF_8);
        SecretKey clave = stringASecretKey(claveString, "AES");
        byte[] iv = Base64.getDecoder().decode(ivString);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clave, new IvParameterSpec(iv));
        byte[] datosCifrados = cipher.doFinal(contenidoArchivo);
        return Base64.getEncoder().encodeToString(datosCifrados);
    }

    public static String descifrarDatosAES(String datosCifradosString, String claveString, String ivString) throws Exception {
        byte[] datosCifrados = Base64.getDecoder().decode(datosCifradosString);
        SecretKey clave = stringASecretKey(claveString, "AES");
        byte[] iv = Base64.getDecoder().decode(ivString);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, clave, new IvParameterSpec(iv));
        byte[] datosDescifrados = cipher.doFinal(datosCifrados);
        return new String(datosDescifrados);
    }
    
    public static SecretKey stringASecretKey(String claveString, String algoritmo) {
        byte[] claveBytes = Base64.getDecoder().decode(claveString);
        return new SecretKeySpec(claveBytes, algoritmo);
    }
}
