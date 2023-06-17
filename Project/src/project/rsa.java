package project;

import javacard.framework.*;
import javacardx.crypto.*;
import javacard.security.*;
import javacard.security.KeyBuilder;

public class rsa extends Applet {
    private Cipher rsaCipher;
    private Signature rsaSig;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    

    private static final byte INS_GENERATE_KEYS = (byte) 0x00;
    private static final byte INS_SEND_MODULUS = (byte) 0x01;
    private static final byte INS_SEND_EXPONENT = (byte) 0x02;
    private static final byte INS_ENCRYPT = (byte) 0x03;
    private static final byte INS_DECRYPT = (byte) 0x04;
    private static final byte INS_SIGN = (byte) 0x05;
    private static final byte INS_VERIFY = (byte) 0x06;
    
    private byte[] sig_buffer;
	private short sigLen;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new rsa().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }
    
    private rsa(){
	    sigLen = (short) (KeyBuilder.LENGTH_RSA_1024 / 8);
		sig_buffer = JCSystem.makeTransientByteArray(sigLen, JCSystem.CLEAR_ON_DESELECT);
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
            case INS_SIGN:
                signData(apdu);
                break;
            case INS_VERIFY:
                verifyData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateKeys() {
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        keyPair.genKeyPair();
    }

    private void sendModulus(APDU apdu) {
        if (publicKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] modulusBytes = new byte[(short) (publicKey.getSize() / 8)];
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

    private void signData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        rsaSig.init(privateKey, Signature.MODE_SIGN);
        
        rsaSig.sign(buffer, ISO7816.OFFSET_CDATA, dataLen, sig_buffer, (short) 0);

        apdu.setOutgoing();
		apdu.setOutgoingLength(sigLen);
		apdu.sendBytesLong(sig_buffer, (short) 0, sigLen);

    }

    private void verifyData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, sig_buffer, (short) 0, sigLen);
		dataLen = (short) (dataLen - sigLen);
        byte[] data = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);
        short cdataOffset = (short) (ISO7816.OFFSET_CDATA + sigLen);
        Util.arrayCopyNonAtomic(buffer, cdataOffset, data, (short) 0, dataLen);

        rsaSig.init(publicKey, Signature.MODE_VERIFY);

        boolean isVerified = rsaSig.verify(data, (short) 0, dataLen, sig_buffer, (short) 0, sigLen);
        
        buffer[(short) 0] = isVerified ? (byte) 1 : (byte) 0;
		apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
}

// Các lnh:

// Send: 00 00 00 00
// => To RSA key

// Send: 00 01 00 00 80
// => Gi modulus (80 là d liu LE)

// Send: 00 02 00 00 80
// => Gi exponent (80 là d liu LE, thc ra ch cn 3 bi exponent ch có  dài là 3bytes)

// Send: 00 03 00 00 06 01 02 03 04 05 06
// => Mã hóa chui 01 02 03 04 05 06 và nhn c bn mã

// Send: 00 04 00 00 80 + bn mã
// => Gii mã và c chui c

// Send: 00 05 00 00 03 01 02 03
// => Ký chui 01 02 03 và nhn c ch ký có  dài 80 bytes

// Send: 00 06 00 00 83 + ch ký + 01 02 03
// => Xác thc ch ký và tr li 1 nu úng, 0 nu sai

