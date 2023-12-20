package hybridcryptography;

public class HybridCryptography {

    public static void main(String[] args) {
        try {            
            String texto = "ABCDEFG-1234567"; 
            
            RSA Emisor = new RSA();
            RSA Receptor = new RSA();
            Emisor.generarRSA();
            Receptor.generarRSA();
            
            Receptor.getModulus();
            
            String iv = AES.generarIV();
            String clave = AES.generarClaveAES();
            
            //Cifrar Mensaje
            String datosCifrados = AES.cifrarAES(texto, clave, iv);
            String claveC = Receptor.cifrar(clave, Receptor.getPublicKey().toString(), Receptor.getModulus().toString());
            String ivC = Receptor.cifrar(iv, Receptor.getPublicKey().toString(), Receptor.getModulus().toString());
            
            //Descifrar Mensaje
            String claveD = Receptor.descifrar(claveC, Receptor.getPrivateKey(), Receptor.getModulus().toString());
            String ivD = Receptor.descifrar(ivC, Receptor.getPrivateKey(), Receptor.getModulus().toString());
            String datosDescifrados = AES.descifrarDatosAES(datosCifrados, claveD, ivD);
            
            //Firmar
            String digesto = Hash.calcularDigestoSHA256(texto);
            String firma = Emisor.cifrar(digesto, Emisor.getPrivateKey().toString(), Emisor.getModulus().toString());
            
            //Verificar
            String firmaDes = Emisor.descifrar(firma, Emisor.getPublicKey(), Emisor.getModulus().toString());
            
            if (digesto.equals(firmaDes)) {
                System.out.println("Firma Verificada");
                System.out.println(datosDescifrados);
            } else {
                System.out.println("Datos vulnerados");
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
