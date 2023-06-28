package project;

import javacard.framework.*; 
import javacardx.crypto.*; 
import javacard.security.*; 
import javacard.security.KeyBuilder; 
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class rsa extends Applet
{
	
    private Cipher rsaCipher;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    private static final byte INS_GENERATE_KEYS = (byte) 0x00;
    private static final byte INS_SEND_MODULUS = (byte) 0x01;
    private static final byte INS_SEND_EXPONENT = (byte) 0x02;
    private static final byte INS_ENCRYPT = (byte) 0x03;
    private static final byte INS_DECRYPT = (byte) 0x04;
		
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new rsa().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	protected rsa() {
		
    }

	
	public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GENERATE_KEYS:
                generateKeys();
                
                break;
            case INS_SEND_MODULUS:
                sendModulus(apdu);
                break;
            case INS_SEND_EXPONENT:
                sendExponent(apdu);
                break;
            case INS_ENCRYPT:
                encryptData(apdu);
                break;
            case INS_DECRYPT:
                decryptData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
	
	private void generateKeys() {
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        keyPair.genKeyPair();
    }
    
    private void sendModulus(APDU apdu) {
		if (publicKey == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		byte[] modulusBytes = new byte[(short) (publicKey.getSize()/8)];
		publicKey.getModulus(modulusBytes, (short) 0);

		short le = apdu.setOutgoing();
		apdu.setOutgoingLength((short) modulusBytes.length);
		apdu.sendBytesLong(modulusBytes, (short) 0, (short) modulusBytes.length);
	}    
	
	private void sendExponent(APDU apdu) {
		if (publicKey == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		byte[] exponentBytes = new byte[(short) 3];
		publicKey.getExponent(exponentBytes, (short) 0);

		short le = apdu.setOutgoing();
		apdu.setOutgoingLength((short) exponentBytes.length);
		apdu.sendBytesLong(exponentBytes, (short) 0, (short) exponentBytes.length);
	}
    
    private void encryptData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short dataLength = apdu.setIncomingAndReceive();
        short le = apdu.setOutgoing();

        rsaCipher.init(publicKey, Cipher.MODE_ENCRYPT);
        short encLength = rsaCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLength, buffer, (short) 0);

        apdu.setOutgoingLength(encLength);
        apdu.sendBytesLong(buffer, (short) 0, encLength);
    }
    
    private void decryptData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short dataLength = apdu.setIncomingAndReceive();
        short le = apdu.setOutgoing();

        rsaCipher.init(privateKey, Cipher.MODE_DECRYPT);
        short decLength = rsaCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLength, buffer, (short) 0);

        apdu.setOutgoingLength(decLength);
        apdu.sendBytesLong(buffer, (short) 0, decLength);
    }
	

}