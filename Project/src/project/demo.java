package project;

import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.*;

public class demo extends Applet
{	
	//ma hoa
	private Cipher cipher;
	private AESKey key;
	
	// C�c tag c s dng  x�c nh loi th�ng tin cn lu tr hoc truy xut
    private static final byte ID_TAG = 0x01;
    private static final byte NAME_TAG = 0x02;
    private static final byte BIRTHDATE_TAG = 0x03;
    private static final byte GENDER_TAG = 0x04;
    private static final byte ADDRESS_TAG = 0x05;
    private static final byte PHONE_TAG = 0x06;
    private static final byte BALANCE_TAG = 0x07;
    
    private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04}; // m� PIN mc nh
    private static final byte MAX_PIN_TRIES = 3; // s ln nhp sai cho ph�p
	private byte[] tempBuffer;

    private OwnerPIN pin; // i tng OwnerPIN  lu tr v� qun l� PIN

    // C�c m� li c s dng trong chng tr�nh
    private static final short SW_INVALID_LENGTH = 0x6A84;
    private static final short SW_INVALID_TAG = 0x6A80;
    private static final short SW_RECORD_NOT_FOUND = 0x6A83;

    // Bin lu tr th�ng tin c� nh�n
    private byte[] id;
    private byte[] name;
    private byte[] birthdate;
    private byte gender;
    private byte[] address;
    private byte[] phone;
    private byte[] balance;

    // Phng thc khi to
    public demo() {
        id = new byte[10];
        name = new byte[50];
        birthdate = new byte[6];
        gender = 0;
        address = new byte[100];
        phone = new byte[11];
        balance = new byte[4];
        tempBuffer = JCSystem.makeTransientByteArray((short) 50, JCSystem.CLEAR_ON_RESET);

        // to mi i tng OwnerPIN
        pin = new OwnerPIN(MAX_PIN_TRIES, (byte) DEFAULT_PIN.length);

        // t gi� tr mc nh cho PIN
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,false);
        key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128, false) ;
  }

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new demo().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	// X l� c�c lnh gi n th
    public void process(APDU apdu) {
		if (selectingApplet()) {
            return;
        }
        
        // Ly c�c byte d liu t APDU buffer
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
                verify(apdu); // gi h�m kim tra m� PIN
                break;
            case (byte) 0x05:
                change(apdu); // gi h�m thay i m� PIN
                break;
			default:
				// Lnh kh�ng c h tr
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
        
    }
    
    // X l� lnh WRITE DATA
    private void writeData(byte[] buffer, APDU apdu, short lc) {
        byte tag = buffer[ISO7816.OFFSET_P1];
        short offset = ISO7816.OFFSET_CDATA;

        // Kim tra  d�i d liu
        if (lc > 255) {
            ISOException.throwIt(SW_INVALID_LENGTH);
        }

        // Ghi d liu v�o bin tng ng
        switch (tag) {
            case ID_TAG:
				// Util.arrayCopy(buffer, offset, id, (short)0, lc);
				Util.arrayCopy(buffer, offset, tempBuffer, (short) 0, lc);
				cipher.init(key,Cipher.MODE_ENCRYPT );
				cipher.doFinal(tempBuffer, (short) 0, lc, tempBuffer, (short) 0);
				
				// copy tempBuffer v�o id
				Util.arrayCopy(tempBuffer, (short) 0, id, (short) 0, lc);
				
				//delete tempBuffer
				Util.arrayFillNonAtomic(tempBuffer, (short) 0, lc, (byte) 0x00);


                break;
            case NAME_TAG:
            	// Util.arrayCopy(buffer, offset, name, (short) 0, lc);
            		Util.arrayCopy(buffer, offset, tempBuffer, (short) 0, lc);
				cipher.init(key,Cipher.MODE_ENCRYPT );
				cipher.doFinal(tempBuffer, (short) 0, lc, tempBuffer, (short) 0);
				
				// copy tempBuffer v�o id
				Util.arrayCopy(tempBuffer, (short) 0, name, (short) 0, lc);
				
				//delete tempBuffer
				Util.arrayFillNonAtomic(tempBuffer, (short) 0, lc, (byte) 0x00);

                break;
            case BIRTHDATE_TAG:
                Util.arrayCopy(buffer, offset, birthdate, (short)0, lc);
                break;
            case GENDER_TAG:
                gender = buffer[offset];
                break;
            case ADDRESS_TAG:
                Util.arrayCopy(buffer, offset, address, (short)0, lc);
                break;
            case PHONE_TAG:
                Util.arrayCopy(buffer, offset, phone, (short)0, lc);
				break;
			case BALANCE_TAG:
				Util.arrayCopy(buffer, offset, balance, (short)0, lc);
				break;
			default:
				// Nu tag kh�ng hp l, gi m� li tr v

				ISOException.throwIt(SW_INVALID_TAG);
		}
	
	}
	
    // X l� lnh READ DATAs
    private void readData(byte[] buffer, APDU apdu) {
        byte tag = buffer[ISO7816.OFFSET_P1];

        // Tr v th�ng tin cn ly
        switch(tag) {
            case ID_TAG:
                sendResponse(apdu, id, (short)0, (short)id.length);
                break;
            case NAME_TAG:
                sendResponse(apdu, name, (short)0, (short)name.length);
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
                // Nu tag kh�ng hp l, gi m� li tr v
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

		// Nu kim tra  d�i d liu c y�u cu bi APDU
		short lengthField = apdu.setOutgoing();
		if (length > lengthField) {
			// D liu c y�u cu qu� d�i  tr v
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}

		// Sao ch�p d liu v�o APDU buffer v� tr v
		Util.arrayCopy(data, offset, buffer, (short)0, length);
		apdu.setOutgoingLength(length);
		apdu.sendBytes((short)0, length);
	}
	
	// Phng thc RESET
	private void resetData() {
		id = new byte[10];
		name = new byte[50];
		birthdate = new byte[6];
		gender = 0;
		address = new byte[100];
		phone = new byte[11];
		balance = new byte[4];
	}

	// Kim tra m� PIN
    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Ly d liu t APDU
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Kim tra m� PIN
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) byteRead)) {
            // Tr v m� th�nh c�ng nu m� PIN �ng
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        } else {
            // Tr s ln nhp sai c�n li nu m� PIN sai
            ISOException.throwIt((short) (0x63C0 + pin.getTriesRemaining()));
        }
    }

    // Thay i m� PIN
    private void change(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Ly d liu t APDU
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Kim tra  d�i ca m� PIN mi
        if (byteRead != 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Thay i m� PIN
        pin.update(buffer, ISO7816.OFFSET_CDATA, (byte) byteRead);

        // Tr v m� th�nh c�ng
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

}
