package project;

import javacard.framework.*;

public class OwnerPIN {
	private byte triesRemaining; // s ln còn li

    private byte[] pin; // mã PIN

    public OwnerPIN(byte maxTries, byte length) {
        triesRemaining = maxTries;
        pin = new byte[length];
    }

    public void update(byte[] buffer, short offset, byte count) {
        Util.arrayCopy(buffer, offset, pin, (short) 0, count);
        reset();
    }

    public boolean check(byte[] buffer, short offset, byte count) {
        boolean result = Util.arrayCompare(buffer, offset, pin, (short) 0, count) == 0;
        if (!result) {
            triesRemaining--;
        }

        return result;
    }

    public byte getTriesRemaining() {
        return triesRemaining;
    }

    public void reset() {
        triesRemaining = (byte) 3; // t li s ln còn li
    }
}
