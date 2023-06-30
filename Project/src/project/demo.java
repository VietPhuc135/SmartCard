package project;

import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.*;

public class demo extends Applet implements masterInterface {
	//ma hoa
	private Cipher cipher;
	private AESKey aesKey;
	private byte[] tempBuffer;
	private byte[] in, enc_buffer, dec_buffer, dec_buffer1, dec_buffer2;
	private short keyLen;
	 private Encrypt encryptor;
	//hambam
	    private MessageDigest sha256;
	    public  byte[] pinHash;

	// Cc tag c s dng  xc nh loi thng tin cn lu tr hoc truy xut
	private static final byte ID_TAG = 0x01;
	private static final byte NAME_TAG = 0x02;
	private static final byte BIRTHDATE_TAG = 0x03;
	private static final byte GENDER_TAG = 0x04;
	private static final byte ADDRESS_TAG = 0x05;
	private static final byte PHONE_TAG = 0x06;
	private static final byte BALANCE_TAG = 0x07;

	private static final byte[] DEFAULT_PIN = { 0x01, 0x02, 0x03, 0x04 }; // m PIN mc nh
	private static final byte MAX_PIN_TRIES = 3; // s ln nhp sai cho php

	private OwnerPIN pin; // i tng OwnerPIN  lu tr v qun l PIN
    
    public boolean isLocked = false;

	// Cc m li c s dng trong chng trnh
	private static final short SW_INVALID_LENGTH = 0x6A84;
	private static final short SW_INVALID_TAG = 0x6A80;
	private static final short SW_RECORD_NOT_FOUND = 0x6A83;

	// Bin lu tr thng tin c nhn
	private byte[] id;
	private byte[] name;
	private byte[] birthdate;
	private byte gender;
	private byte[] address;
	private byte[] phone;
	private byte[] balance;

	// Phng thc khi to
	public demo() {
		id = new byte[16];
		name = new byte[48];
		birthdate = new byte[16];
		gender = 0;
		address = new byte[112];
		phone = new byte[16];
		balance = new byte[16];
		tempBuffer = JCSystem.makeTransientByteArray((short) 50, JCSystem.CLEAR_ON_RESET);
		pinHash = new byte[16];
		// to mi i tng OwnerPIN
		pin = new OwnerPIN(MAX_PIN_TRIES, (byte) DEFAULT_PIN.length);

		// t gi tr mc nh cho PIN
		pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);

		// ma hoa
		// aes= new AesConfig();
		keyLen = (short) (KeyBuilder.LENGTH_AES_128 / 8);

		// in = new byte[keyLen];
		enc_buffer = new byte[keyLen];
		dec_buffer = new byte[48];
		dec_buffer1 = new byte[16];
		dec_buffer2 =  new byte[112];

		// ham bam
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_MD5,false);
		sha256.reset();
		sha256.doFinal(DEFAULT_PIN, (short) 0, (short) DEFAULT_PIN.length, pinHash, (short) 0);
		 aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        
		 cipher = Cipher.getInstance(javacardx.crypto.Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
 
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new demo().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	// X l cc lnh gi n th
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		// Ly cc byte d liu t APDU buffer
		byte[] buffer = apdu.getBuffer();
		short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

		switch (buffer[ISO7816.OFFSET_INS]) {
			case (byte) 0x01:
				// Lnh WRITE DATA
				if (isLocked) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				writeData(buffer, apdu, lc);
				break;
			case (byte) 0x02:
				// Lnh READ DATA
				if (isLocked) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				readData(buffer, apdu);
				break;
			case (byte) 0x03:
				// Lnh RESET
				if (isLocked) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				resetData();
				break;
			case (byte) 0x04:
				if (isLocked) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				verify(apdu); // gi hm kim tra m PIN
				break;
			case (byte) 0x05:
				if (isLocked) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				change(apdu); // gi hm thay i m PIN
				break;
			case (byte) 0x06: // khoa the
				isLocked = true;
				break;
			case (byte) 0x07: // mo the
				isLocked = false;
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

  private void addPadding(byte[] data, short offset, short length) {
        byte paddingLength = (byte) (16 - (length % 16));
        byte padValue = paddingLength;
        for (short i =(short)(offset + length); i < offset + length + paddingLength; i++) {
            data[i] = padValue;
        }
    }

      private void encryptData(byte[] input, short inputOffset, byte[] output, short outputOffset, short length,AESKey aesKey) {
      	 if (length % 16 != 0) {
            addPadding(input, inputOffset, length);
            length += (16 - (length % 16));
        }
        cipher.init(aesKey, Cipher.MODE_ENCRYPT);
        cipher.doFinal(input, inputOffset, length, output, outputOffset);
    }

    // Gii mã d liu bng AES
    private void decryptData(byte[] input, short inputOffset, byte[] output, short outputOffset, short length,AESKey aesKey) {
        cipher.init(aesKey, Cipher.MODE_DECRYPT);
        cipher.doFinal(input, inputOffset, length, output, outputOffset);
    }
    private void decryptData2(byte[] input, short inputOffset, byte[] output, short outputOffset, short length, AESKey aesKey, byte[] output2) {
    cipher.init(aesKey, Cipher.MODE_DECRYPT);
    cipher.doFinal(input, inputOffset, length, output, outputOffset);

    // Xóa padding
    byte paddingLength = output[(short) (outputOffset + length - 1)];
    short decryptedLength = (short) (length - paddingLength);
    
    // Sao chép d liu gii mã vào mng decryptedData
    byte[] decryptedData = new byte[decryptedLength];
    Util.arrayCopyNonAtomic(output, outputOffset, decryptedData, (short) 0, decryptedLength);
}

    
    // X lý lnh WRITE DATA
    private void writeData(byte[] buffer, APDU apdu, short lc) {
        byte tag = buffer[ISO7816.OFFSET_P1];
        short offset = ISO7816.OFFSET_CDATA;
        aesKey.setKey(pinHash, (short) 0);
        short byteRead = (short) (apdu.setIncomingAndReceive());
        // Kim tra  dài d liu
        if (lc > 255) {
            ISOException.throwIt(SW_INVALID_LENGTH);
        }
        
        short pointer = 0;

        // Ghi d liu vào bin tng ng
        switch (tag) {
        	
			case NAME_TAG:
				// encryptData(buffer, offset, name, (short) 0, lc,aesKey);
				
				while(lc > 0){
					// name =  encryptor.encryptData(buffer, offset,  name, lc, keyLen,aesKey);
					Util.arrayCopy(buffer, offset, name, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}
				break;
	
            case ID_TAG:
				// encryptor.encryptData(buffer, offset,  id, lc, keyLen,DEFAULT_PIN);
				while(lc > 0){
					Util.arrayCopy(buffer, offset, id, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}
                break;
       
            case BIRTHDATE_TAG:
            	
            		// encryptData(buffer, offset, birthdate, (short) 0, lc,aesKey);
                while(lc > 0){
                	byte[] bufd = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, birthdate, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				
				}
                break;
            case GENDER_TAG:
                gender = buffer[offset];
                break;
            case ADDRESS_TAG:
            		// encryptData(buffer, offset, address, (short) 0, lc,aesKey);
              // encryptor.encryptData(buffer, offset,  address, lc, keyLen,DEFAULT_PIN);
                while(lc > 0){
                	byte[] bufa = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, address, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
					
				}
                break;
            case PHONE_TAG:
            			// encryptData(buffer, offset, phone, (short) 0, lc,aesKey);
               // encryptor.encryptData(buffer, offset,  phone, lc, keyLen,DEFAULT_PIN);
                while(lc > 0){
                	byte[] bufp = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, phone, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
					
				}
				break;
			case BALANCE_TAG:
						// encryptData(buffer, offset, balance, (short) 0, lc,aesKey);
				// encryptor.encryptData(buffer, offset,  balance, lc, keyLen,DEFAULT_PIN);
				JCSystem.beginTransaction();
				while(lc > 0){
					byte[] bufb = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, balance, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}
				JCSystem.commitTransaction();

				break;
			default:
				// Nu tag không hp l, gi mã li tr v
				ISOException.throwIt(SW_INVALID_TAG);
		}
	
	
    }
	
    // X lý lnh READ DATAs
    private void readData(byte[] buffer, APDU apdu) {
        byte tag = buffer[ISO7816.OFFSET_P1];
		short offset = ISO7816.OFFSET_CDATA;
		
        // Tr v thông tin cn ly
        switch(tag) {
            case ID_TAG:
                sendResponse(apdu, id, (short)0, (short)id.length);
                break;
            case NAME_TAG: 
            	sendResponse(apdu, name, (short)0, (short)name.length);
				// decryptData2(name, (short) 0, dec_buffer, (short) 0, (short) name.length,aesKey,);
                // sendResponse(apdu, dec_buffer, (short) 0, (short) dec_buffer.length);
				
                break;
            case BIRTHDATE_TAG:
            	            	
				// decryptData(birthdate, (short) 0, dec_buffer1, (short) 0, (short) birthdate.length,aesKey);
                // sendResponse(apdu, dec_buffer1, (short) 0, (short) dec_buffer1.length);
                
                sendResponse(apdu, birthdate, (short)0, (short)birthdate.length);
                break;
            case GENDER_TAG:
            	
                sendResponse(apdu, new byte[] { gender }, (short)0, (short)1);
                break;
            case ADDRESS_TAG:
            			// decryptData(address, (short) 0, dec_buffer2, (short) 0, (short) address.length,aesKey);
                // sendResponse(apdu, dec_buffer2, (short) 0, (short) dec_buffer2.length);
                sendResponse(apdu, address, (short)0, (short)address.length);
                break;
            case PHONE_TAG:
            	// decryptData(phone, (short) 0, dec_buffer, (short) 0, (short) phone.length,aesKey);
                // sendResponse(apdu, dec_buffer, (short) 0, (short) dec_buffer.length);
             
                sendResponse(apdu, phone, (short)0, (short)phone.length);
                break;
            case BALANCE_TAG:
            	// decryptData(balance, (short) 0, dec_buffer1, (short) 0, (short) balance.length,aesKey);
                // sendResponse(apdu, dec_buffer1, (short) 0, (short) dec_buffer1.length);
             
                sendResponse(apdu, balance, (short)0, (short)balance.length);
                break;
            default:
                // Nu tag không hp l, gi mã li tr v
                ISOException.throwIt(SW_RECORD_NOT_FOUND);
        }
      
    }

	// Phng thc gi d liu tr v
	private void sendResponse(APDU apdu, byte[] data, short offset, short length) {
		byte[] buffer = apdu.getBuffer();

		// Nu kim tra  di d liu c yu cu bi APDU
		short lengthField = apdu.setOutgoing();
		if (length > lengthField) {
			// D liu c yu cu qu di  tr v
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Sao chp d liu vo APDU buffer v tr v
		Util.arrayCopy(data, offset, buffer, (short) 0, length);
		apdu.setOutgoingLength(length);
		apdu.sendBytes((short) 0, length);
	}

	// Phng thc RESET
	private void resetData() {
		//id = new byte[16];
		name = new byte[50];
		birthdate = new byte[16];
		gender = 0;
		address = new byte[100];
		phone = new byte[16];
		balance = new byte[16];
		id = new byte[16];
		
		
	}

	// Kim tra m PIN
	private void verify(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		// Ly d liu t APDU
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// Kim tra m PIN
		if (pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) byteRead)) {
			// Tr v m thnh cng nu m PIN ng
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		} else {
			// Tr s ln nhp sai cn li nu m PIN sai
			ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
		}
	}

	// Thay i m PIN
	private void change(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		// Ly d liu t APDU
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// Kim tra  di ca m PIN mi
		if (byteRead != 4) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Thay i m PIN
		pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) byteRead);

		// Tr v m thnh cng
		ISOException.throwIt(ISO7816.SW_NO_ERROR);
	}
	
	public Shareable getShareableInterfaceObject (AID clientAID, byte parameter){
		
		// xacs thuc nguoi dungf
		if(parameter != (byte)0x00)	
			return null;
		
		return this;
	}
	
	public boolean getIsLocked() {
        return isLocked;
    }

}
