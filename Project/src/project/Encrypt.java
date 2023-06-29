package project;
import javacard.security.MessageDigest;
import javacard.security.KeyBuilder;
import javacard.security.AESKey;
import javacard.security.*;
import javacardx.crypto.Cipher;
import javacard.framework.*;

public class Encrypt {
    private Cipher cipher;
    private MessageDigest sha256;
    private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};	
    
    public Encrypt() {
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        
    }
    
    public void encryptData(byte[] buffer, short offset, byte[] data, short dataOffset, short length, byte[] pin) {
        // To khóa t DEFAULT_PIN
        byte[] pinHash = new byte[32];
        sha256.reset();
        //tinh toan ham 
        sha256.doFinal(pin, (short) 0, (short) pin.length, pinHash, (short) 0);
        
        // Khi to khóa AES t pinHash
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(pinHash, (short) 0);
        
        byte[] paddedData = new byte[(short) (length + 16)]; //tao mang voi do dai tang them 16byte de chua padding
		Util.arrayCopyNonAtomic(data, dataOffset, paddedData, (short) 0, length); // copy data vao mang moi

			// Thuc hien padding PKCS5
		byte paddingLength = (byte) (16 - (length % 16)); // tinh do dai padding
		for (short i = length; i < length + paddingLength; i++) {
				paddedData[i] = paddingLength;
			}

        // Ma hoa du lieu
        cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        cipher.doFinal(buffer, offset, length, data, dataOffset);
    }

}
