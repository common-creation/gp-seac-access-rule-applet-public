/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.globalplatform;

import javacard.framework.*;

/** Deterministic fake of the card OS for protocol tests; does not implement SCP03 cryptography. */
public final class SecureChannel {
    public static final byte AUTHENTICATED = (byte) 0x80;
    public static final byte C_MAC = 1;
    private byte level;
    public byte protocol = 3;
    public boolean rejectMac;
    public void resetSecurity() { level = 0; rejectMac = false; }
    public byte getSecurityLevel() { return level; }
    public short processSecurity(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] b = apdu.getBuffer();
        if (b[1] == 0x50) {
            level = 0;
            b[ISO7816.OFFSET_CDATA + 11] = protocol;
            return 29;
        }
        level = (byte) (0x80 | b[2]);
        return 0;
    }
    public short unwrap(byte[] data, short offset, short length) {
        boolean markerValid = length >= 13;
        for (short i = (short) (length - 8); markerValid && i < length; i++) {
            markerValid = data[i] == (byte) 0xA5;
        }
        if (rejectMac || !markerValid) {
            level = 0;
            ISOException.throwIt((short) 0x6982);
        }
        data[4] -= 8;
        return (short) (length - 8);
    }
}
