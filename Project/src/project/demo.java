package project;

import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.*;

public class demo extends Applet
{	
	//ma hoa
	private Cipher cipher;
	private AESKey aesKey;
	private byte[] tempBuffer;
	private byte[] in, enc_buffer, dec_buffer;
	private short keyLen;
	 private Encrypt encryptor;
	//hambam
	    private MessageDigest sha256;
	    public  byte[] pinHash;
    // private byte[] pin;
	
	// Các tag c s dng  xác nh loi thông tin cn lu tr hoc truy xut
    private static final byte ID_TAG = 0x01;
    private static final byte NAME_TAG = 0x02;
    private static final byte BIRTHDATE_TAG = 0x03;
    private static final byte GENDER_TAG = 0x04;
    private static final byte ADDRESS_TAG = 0x05;
    private static final byte PHONE_TAG = 0x06;
    private static final byte BALANCE_TAG = 0x07;
    
    private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04}; // mã PIN mc nh
    private static final byte MAX_PIN_TRIES = 3; // s ln nhp sai cho phép
	
    private OwnerPIN pin; // i tng OwnerPIN  lu tr và qun lý PIN

    // Các mã li c s dng trong chng trình
    private static final short SW_INVALID_LENGTH = 0x6A84;
    private static final short SW_INVALID_TAG = 0x6A80;
    private static final short SW_RECORD_NOT_FOUND = 0x6A83;

    // Bin lu tr thông tin cá nhân
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
        name = new byte[50];
        birthdate = new byte[16];
        gender = 0;
        address = new byte[100];
        phone = new byte[16];
        balance = new byte[16];
        tempBuffer = JCSystem.makeTransientByteArray((short) 50, JCSystem.CLEAR_ON_RESET);
		 pinHash = new byte[32];
        // to mi i tng OwnerPIN
        pin = new OwnerPIN(MAX_PIN_TRIES, (byte) DEFAULT_PIN.length);

        // t giá tr mc nh cho PIN
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
        
        //ma hoa
        encryptor = new Encrypt();
        keyLen = (short)(KeyBuilder.LENGTH_AES_128/8);
       
		// in = new byte[keyLen];
		enc_buffer = new byte[keyLen];
		dec_buffer= new byte[keyLen];
		
		//ham bam
		  sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
				// sha256.reset();
		sha256.doFinal(DEFAULT_PIN, (short) 0, (short) DEFAULT_PIN.length, pinHash, (short) 0);
		 aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(pinHash, (short) 0);
		
  }

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new demo().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	// X lý các lnh gi n th
    public void process(APDU apdu) {
		if (selectingApplet()) {
            return;
        }
        
        // Ly các byte d liu t APDU buffer
        byte[] buffer = apdu.getBuffer();
        short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
        
		switch(buffer[ISO7816.OFFSET_INS]) {
			case (byte) 0x01:
				// Lnh WRITE DATA
				writeData(buffer, apdu, lc);
				break;
			case (byte) 0x02:
				// Lnh READ DATA
				readData(buffer, apdu);
				break;
			case (byte) 0x03:
				// Lnh RESET
				resetData();
				break;
			case (byte) 0x04:
                verify(apdu); // gi hàm kim tra mã PIN
                break;
            case (byte) 0x05:
                change(apdu); // gi hàm thay i mã PIN
                break;
			default:
				// Lnh không c h tr
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
        
    }
    
    // X lý lnh WRITE DATA
    private void writeData(byte[] buffer, APDU apdu, short lc) {
        byte tag = buffer[ISO7816.OFFSET_P1];
        short offset = ISO7816.OFFSET_CDATA;
        
        short byteRead = (short) (apdu.setIncomingAndReceive());
        // Kim tra  dài d liu
        if (lc > 255) {
            ISOException.throwIt(SW_INVALID_LENGTH);
        }
        
        short pointer = 0;

        // Ghi d liu vào bin tng ng
        switch (tag) {
        	
			case NAME_TAG:
				// encryptor.encryptData(buffer, offset,  name, lc, keyLen,aesKey);
				// encryptor.decryptData(name, offset, bufd, (short) 0, lc, pinHash);
				// sendResponse(apdu, bufd, (short) 0, (short) bufd.length);
					while(lc > 0){
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
              // encryptor.encryptData(buffer, offset,  birthdate, lc, keyLen,DEFAULT_PIN);
                while(lc > 0){
                	byte[] bufd = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufd, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				
				}
                break;
            case GENDER_TAG:
                gender = buffer[offset];
                break;
            case ADDRESS_TAG:
              // encryptor.encryptData(buffer, offset,  address, lc, keyLen,DEFAULT_PIN);
                while(lc > 0){
                	byte[] bufa = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufa, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				
				}
                break;
            case PHONE_TAG:
               // encryptor.encryptData(buffer, offset,  phone, lc, keyLen,DEFAULT_PIN);
                while(lc > 0){
                	byte[] bufp = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufp, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
					
				}
				break;
			case BALANCE_TAG:
				// encryptor.encryptData(buffer, offset,  balance, lc, keyLen,DEFAULT_PIN);
				while(lc > 0){
					byte[] bufb = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufb, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}

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
            		// byte[] namenew = apdu.getBuffer();
					// encryptor.decryptData(namenew, offset, name, (short) 0,(short)name.length, aesKey);

            
                sendResponse(apdu, name, (short)0, (short)name.length);
            	// // encryptor.decryptData(name, offset, buffer, offset, (short) name.length, pinHash);
				// byte[] decryptedData = new byte[keyLen];
                 // encryptor.decryptData(namenew,  (short) 0, name, (short) 0, keyLen, aesKey);
				 // Util.arrayCopy(namenew, (short)0,decryptedData, (short)0, keyLen);
                sendResponse(apdu, namenew, (short)0, (short)namenew.length);
                // sendResponse(apdu, decryptedData, (short)0, (short)decryptedData.length);
                // apdu.setOutgoingAndSend((short)0, keyLen);
                break;
            case BIRTHDATE_TAG:
                sendResponse(apdu, birthdate, (short)0, (short)birthdate.length);
                break;
            case GENDER_TAG:
                sendResponse(apdu, new byte[] { gender }, (short)0, (short)1);
                break;
            case ADDRESS_TAG:
                sendResponse(apdu, address, (short)0, (short)address.length);
                break;
            case PHONE_TAG:
                sendResponse(apdu, phone, (short)0, (short)phone.length);
                break;
            case BALANCE_TAG:
                sendResponse(apdu, balance, (short)0, (short)balance.length);
                break;
            default:
                // Nu tag không hp l, gi mã li tr v
                ISOException.throwIt(SW_RECORD_NOT_FOUND);
        }
         // Giai ma
        // if (tag == ID_TAG || tag == NAME_TAG) {
            // cipher.init(pin, Cipher.MODE_DECRYPT);
            // cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) buffer.length, buffer, ISO7816.OFFSET_CDATA);
        // }
    }

    // Phng thc gi d liu tr v
	private void sendResponse(APDU apdu, byte[] data, short offset, short length) {
		byte[] buffer = apdu.getBuffer();

		// Nu kim tra  dài d liu c yêu cu bi APDU
		short lengthField = apdu.setOutgoing();
		if (length > lengthField) {
			// D liu c yêu cu quá dài  tr v
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Sao chép d liu vào APDU buffer và tr v
		Util.arrayCopy(data, offset, buffer, (short)0, length);
		apdu.setOutgoingLength(length);
		apdu.sendBytes((short)0, length);
	}
	
	// Phng thc RESET
	private void resetData() {
		id = new byte[16];
		name = new byte[50];
		birthdate = new byte[16];
		gender = 0;
		address = new byte[100];
		phone = new byte[16];
		balance = new byte[16];
	}

	// Kim tra mã PIN
    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Ly d liu t APDU
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Kim tra mã PIN
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) byteRead)) {
            // Tr v mã thành công nu mã PIN úng
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        } else {
            // Tr s ln nhp sai còn li nu mã PIN sai
            ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
        }
    }

    // Thay i mã PIN
    private void change(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Ly d liu t APDU
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Kim tra  dài ca mã PIN mi
        if (byteRead != 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Thay i mã PIN
        pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) byteRead);

        // Tr v mã thành công
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

}
