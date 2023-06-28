package project;

import javacard.framework.*;
import javacardx.crypto.Cipher;
import javacard.security.*;

public class demo extends Applet implements masterInterface {
	// ma hoa
	private Cipher cipher;
	private AESKey aesKey;
	private byte[] tempBuffer;
	private byte[] in, enc_buffer, dec_buffer;
	private short keyLen;
	private Encrypt encryptor;
	// hambam
	private MessageDigest sha256;
	public byte[] pinHash;
	// private byte[] pin;

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

		// t gi tr mc nh cho PIN
		pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);

		// ma hoa
		encryptor = new Encrypt();
		keyLen = (short) (KeyBuilder.LENGTH_AES_128 / 8);

		// in = new byte[keyLen];
		enc_buffer = new byte[keyLen];
		dec_buffer = new byte[keyLen];

		// ham bam
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		// sha256.reset();
		sha256.doFinal(DEFAULT_PIN, (short) 0, (short) DEFAULT_PIN.length, pinHash, (short) 0);
		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
		aesKey.setKey(pinHash, (short) 0);

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

	// X l lnh WRITE DATA
	private void writeData(byte[] buffer, APDU apdu, short lc) {
		byte tag = buffer[ISO7816.OFFSET_P1];
		short offset = ISO7816.OFFSET_CDATA;

		short byteRead = (short) (apdu.setIncomingAndReceive());
		// Kim tra  di d liu
		if (lc > 255) {
			ISOException.throwIt(SW_INVALID_LENGTH);
		}

		short pointer = 0;

		// Ghi d liu vo bin tng ng
		switch (tag) {

			case NAME_TAG:
				// encryptor.encryptData(buffer, offset, name, lc, keyLen,aesKey);
				// encryptor.decryptData(name, offset, bufd, (short) 0, lc, pinHash);
				// sendResponse(apdu, bufd, (short) 0, (short) bufd.length);
				while (lc > 0) {
					Util.arrayCopy(buffer, offset, name, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}
				break;

			case ID_TAG:
				// encryptor.encryptData(buffer, offset, id, lc, keyLen,DEFAULT_PIN);
				while (lc > 0) {
					Util.arrayCopy(buffer, offset, id, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}
				break;

			case BIRTHDATE_TAG:
				// encryptor.encryptData(buffer, offset, birthdate, lc, keyLen,DEFAULT_PIN);
				while (lc > 0) {
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
				// encryptor.encryptData(buffer, offset, address, lc, keyLen,DEFAULT_PIN);
				while (lc > 0) {
					byte[] bufa = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufa, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);

				}
				break;
			case PHONE_TAG:
				// encryptor.encryptData(buffer, offset, phone, lc, keyLen,DEFAULT_PIN);
				while (lc > 0) {
					byte[] bufp = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufp, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);

				}
				break;
			case BALANCE_TAG:
				// encryptor.encryptData(buffer, offset, balance, lc, keyLen,DEFAULT_PIN);
				while (lc > 0) {
					byte[] bufb = apdu.getBuffer();
					Util.arrayCopy(buffer, offset, bufb, pointer, byteRead);
					pointer += byteRead;
					lc -= byteRead;
					byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}

				break;
			default:
				// Nu tag khng hp l, gi m li tr v
				ISOException.throwIt(SW_INVALID_TAG);
		}

	}

	// X l lnh READ DATAs
	private void readData(byte[] buffer, APDU apdu) {
		byte tag = buffer[ISO7816.OFFSET_P1];
		short offset = ISO7816.OFFSET_CDATA;
		// Tr v thng tin cn ly
		switch (tag) {
			case ID_TAG:
				sendResponse(apdu, id, (short) 0, (short) id.length);
				break;
			case NAME_TAG:
				// byte[] namenew = apdu.getBuffer();
				// encryptor.decryptData(namenew, offset, name, (short) 0,(short)name.length,
				// aesKey);

				sendResponse(apdu, name, (short) 0, (short) name.length);
				// // encryptor.decryptData(name, offset, buffer, offset, (short) name.length,
				// pinHash);
				// byte[] decryptedData = new byte[keyLen];
				// encryptor.decryptData(namenew, (short) 0, name, (short) 0, keyLen, aesKey);
				// Util.arrayCopy(namenew, (short)0,decryptedData, (short)0, keyLen);
				// sendResponse(apdu, namenew, (short)0, (short)namenew.length);
				// sendResponse(apdu, decryptedData, (short)0, (short)decryptedData.length);
				// apdu.setOutgoingAndSend((short)0, keyLen);
				break;
			case BIRTHDATE_TAG:
				sendResponse(apdu, birthdate, (short) 0, (short) birthdate.length);
				break;
			case GENDER_TAG:
				sendResponse(apdu, new byte[] { gender }, (short) 0, (short) 1);
				break;
			case ADDRESS_TAG:
				sendResponse(apdu, address, (short) 0, (short) address.length);
				break;
			case PHONE_TAG:
				sendResponse(apdu, phone, (short) 0, (short) phone.length);
				break;
			case BALANCE_TAG:
				sendResponse(apdu, balance, (short) 0, (short) balance.length);
				break;
			default:
				// Nu tag khng hp l, gi m li tr v
				ISOException.throwIt(SW_RECORD_NOT_FOUND);
		}
		// Giai ma
		// if (tag == ID_TAG || tag == NAME_TAG) {
		// cipher.init(pin, Cipher.MODE_DECRYPT);
		// cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) buffer.length, buffer,
		// ISO7816.OFFSET_CDATA);
		// }
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
		id = new byte[16];
		name = new byte[50];
		birthdate = new byte[16];
		gender = 0;
		address = new byte[100];
		phone = new byte[16];
		balance = new byte[16];
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
