// package project;
// import javacard.security.MessageDigest;
// import javacard.security.KeyBuilder;
// import javacard.security.AESKey;
// import javacard.security.*;
// import javacardx.crypto.Cipher;
// import javacard.framework.*;

// public class Encrypt {
    // public static void encryptData(byte[] buffer, short offset, short lc, byte[] destination, Cipher cipher, SecretKey aesKey) {
        // short pointer = 0;
        // short keyLen = aesKey.getSize();
        // byte[] encBuffer = new byte[keyLen];
        // short byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        
        // while (lc > 0) {
            // byte[] buf = apdu.getBuffer();
            // Util.arrayCopy(buffer, offset, buf, pointer, byteRead);
            // pointer += byteRead;
            // lc -= byteRead;
            // byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);

            // cipher.init(aesKey, Cipher.MODE_ENCRYPT);
            // cipher.doFinal(buf, (short) 0, keyLen, encBuffer, (short) 0);
            // Util.arrayCopy(encBuffer, (short) 0, destination, (short) 0, keyLen);

            // Util.arrayFillNonAtomic(encBuffer, (short) 0, byteRead, (byte) 0x00);
        // }
    // }
// }


// public class Encrypt {
    // private Cipher cipher;
    // private MessageDigest sha256;
    // private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};	
    
    // public Encrypt() {
        // cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        // sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        
    // }
    
    // public void encryptData(byte[] buffer, short offset, byte[] data, short dataOffset, short length, byte[] pin) {
        // // To khóa t DEFAULT_PIN
        // byte[] pinHash = new byte[32];
        // sha256.reset();
        // //tinh toan ham 
        // sha256.doFinal(pin, (short) 0, (short) pin.length, pinHash, (short) 0);
        
        // // Khi to khóa AES t pinHash
        // AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        // aesKey.setKey(pinHash, (short) 0);
        
        // byte[] paddedData = new byte[(short) (length + 16)]; //tao mang voi do dai tang them 16byte de chua padding
		// Util.arrayCopyNonAtomic(data, dataOffset, paddedData, (short) 0, length); // copy data vao mang moi

			// // Thuc hien padding PKCS5
		// byte paddingLength = (byte) (16 - (length % 16)); // tinh do dai padding
		// for (short i = length; i < length + paddingLength; i++) {
				// paddedData[i] = paddingLength;
			// }

        // // Ma hoa du lieu
        // cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        // cipher.doFinal(buffer, offset, length, data, dataOffset);
    // }
// }
package project;
import javacard.security.MessageDigest;
import javacard.security.KeyBuilder;
import javacard.security.AESKey;
import javacard.security.*;
import javacardx.crypto.Cipher;
import javacard.framework.*;

public class Encrypt {
    private Cipher cipher;
    
    public Encrypt() {
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        
    }
    
    public void encryptData(byte[] buffer, short offset, byte[] data, short dataOffset, short length,AESKey aesKey) {
        
        // Khi to khóa AES t pinHash
              
        // byte[] paddedData = new byte[(short) (length + 16)]; //tao mang voi do dai tang them 16byte de chua padding
		// Util.arrayCopyNonAtomic(data, dataOffset, paddedData, (short) 0, length); // copy data vao mang moi

			// // Thuc hien padding PKCS5
		// byte paddingLength = (byte) (16 - (length % 16)); // tinh do dai padding
		// for (short i = length; i < length + paddingLength; i++) {
				// paddedData[i] = paddingLength;
			// }

        // Ma hoa du lieu
        // cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        // cipher.doFinal(buffer, offset, length, data, dataOffset);
        
        
        ///new 
         if (aesKey == null) {
            throw new ISOException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        // Padding PKCS#5
        short paddedLength = (short) (length + (16 - (length % 16)));
        byte[] paddedData = new byte[paddedLength];
        Util.arrayCopyNonAtomic(data, dataOffset, paddedData, (short) 0, length);
        for (short i = length; i < paddedLength; i++) {
            paddedData[i] = (byte) (paddedLength - length);
        }
        
        cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        cipher.doFinal(paddedData, (short) 0, paddedLength, data, offset);
    }
        

    // public void decryptData(byte[] buffer, short offset, byte[] encryptedData, short encryptedDataOffset, short length,AESKey aesKey) {
 
    // // Khi to khóa AES t pinHash
    
    // // Gii mã d liu
    // cipher.init(aesKey, Cipher.MODE_DECRYPT);
    // // cipher.doFinal(encryptedData, encryptedDataOffset, length, buffer, offset);
    // cipher.doFinal(encryptedData, (short)0, length, buffer, (short)0);

    // // Xóa padding PKCS5
    // // byte paddingLength = encryptedData[(short) (encryptedDataOffset + length - 1)];
    // // short decryptedLength = (short) (length - paddingLength);
    // // Util.arrayCopyNonAtomic(encryptedData, encryptedDataOffset, buffer, offset, length);
    
 
// }

//new 
    // public void decryptData(byte[] buffer, short offset, byte[] encryptedData, short encryptedDataOffset, short length, AESKey aesKey) {
      
        // cipher.init(aesKey, Cipher.MODE_DECRYPT);
        // cipher.doFinal(encryptedData, encryptedDataOffset, length, buffer, offset);
    // }
	public void decryptData(byte[] buffer, short offset, byte[] encryptedData, short encryptedDataOffset, short length, AESKey aesKey) {
	if (aesKey == null) {
            throw new ISOException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
    // Khoi tao khóa AES tu aesKey
    cipher.init(aesKey, Cipher.MODE_DECRYPT);
    cipher.doFinal(encryptedData, encryptedDataOffset, length, buffer, offset);
    
    // Xoa padding PKCS5
    byte paddingLength = buffer[(short) (offset + length - 1)];
    short decryptedLength = (short) (length - paddingLength);
    Util.arrayCopyNonAtomic(buffer, offset, buffer, offset, decryptedLength);
}

}
