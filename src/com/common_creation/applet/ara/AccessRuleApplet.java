/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.common_creation.applet.ara;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/** Shared source compiled into each CAP's own package, with independent storage. */
public abstract class AccessRuleApplet extends Applet {
    private static final short SLOTS = 16;
    private static final short HASH_SIZE = 32;
    // Zero is a present wildcard (C1 00); -1 means an unused slot.
    private static final byte EMPTY = (byte) -1;
    private static final short ALL = (short) 0xFF40;
    private static final short NEXT = (short) 0xFF60;
    private static final short REFRESH = (short) 0xDF20;
    private static final short CONFIG = (short) 0xDF21;
    private static final short HASHES = (short) 0xDF22;
    private static final short POS = 0;
    private static final short END = 1;
    private static final short KIND = 2;
    private static final short SCP03 = 3;
    private static final short CONFIG_ALLOWED = 4;
    private static final short RULES = 1;
    private static final short RESPONSE = 2;
    private static final short INVALIDATED = 3;

    private final boolean master;
    private final byte[] hashes;
    private final byte[] lengths;
    private final byte[] refresh;
    private final RandomData random;
    private final byte[] output;
    private final byte[] newRefresh;
    private final short[] state;
    private SecureChannel channel;

    protected AccessRuleApplet(boolean master, byte[] parameters, short offset, byte length) {
        this.master = master;
        hashes = new byte[SLOTS * HASH_SIZE];
        lengths = new byte[SLOTS];
        Util.arrayFillNonAtomic(lengths, (short) 0, SLOTS, EMPTY);
        refresh = new byte[8];
        // 16 * (two SHA-256 rules, 106 bytes) + BER header.
        output = JCSystem.makeTransientByteArray((short) 1701, JCSystem.CLEAR_ON_DESELECT);
        newRefresh = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        state = JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_DESELECT);
        installHashes(parameters, offset, (short) (length & 0xFF));
        // Some native card services require the applet to be registered first.
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        random.generateData(refresh, (short) 0, (short) 8);
    }

    private void installHashes(byte[] data, short offset, short length) {
        short end = (short) (offset + length);
        require(length >= 3 && offset >= 0 && end <= data.length, ISO7816.SW_WRONG_DATA);
        short aidLength = (short) (data[offset] & 0xFF);
        short aidOffset = (short) (offset + 1);
        short pos = (short) (aidOffset + aidLength);
        require(aidLength >= 5 && aidLength <= 16 && pos < end, ISO7816.SW_WRONG_DATA);
        short privilegesLength = (short) (data[pos++] & 0xFF);
        pos += privilegesLength;
        require(pos < end, ISO7816.SW_WRONG_DATA);
        short parameterLength = (short) (data[pos++] & 0xFF);
        require((short) (pos + parameterLength) == end, ISO7816.SW_WRONG_DATA);
        short slot = 0;
        while (pos < end) {
            require(slot < SLOTS, ISO7816.SW_FILE_FULL);
            require((short) (end - pos) >= 2, ISO7816.SW_WRONG_DATA);
            short size = (short) (data[(short) (pos + 1)] & 0xFF);
            require(data[pos] == (byte) 0xC1 && (size == 0 || size == 20 || size == 32)
                    && (short) (pos + 2 + size) <= end, ISO7816.SW_WRONG_DATA);
            pos += 2;
            require(find(data, pos, size) < 0, ISO7816.SW_WRONG_DATA);
            Util.arrayCopyNonAtomic(data, pos, hashes, (short) (slot * HASH_SIZE), size);
            lengths[slot++] = (byte) size;
            pos += size;
        }
        register(data, aidOffset, (byte) aidLength);
    }

    public boolean select() {
        channel = GPSystem.getSecureChannel();
        channel.resetSecurity();
        state[SCP03] = 0;
        state[KIND] = 0;
        state[CONFIG_ALLOWED] = 1;
        return true;
    }

    public void deselect() {
        if (channel != null) {
            channel.resetSecurity();
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];
        short parameter = Util.getShort(buffer, ISO7816.OFFSET_P1);
        boolean configAllowed = state[CONFIG_ALLOWED] != 0;
        state[CONFIG_ALLOWED] = 0;
        require(!apdu.isCommandChainingCLA(), ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
        if (ins == (byte) 0xC0) {
            require(!apdu.isSecureMessagingCLA(), ISO7816.SW_CLA_NOT_SUPPORTED);
            require(parameter == 0, ISO7816.SW_INCORRECT_P1P2);
            require(state[KIND] == RESPONSE, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            send(apdu, true);
            return;
        }
        require((cla & 0x80) != 0, ISO7816.SW_CLA_NOT_SUPPORTED);
        if (ins == (byte) 0x50 || ins == (byte) 0x82) {
            authenticate(apdu, ins);
            return;
        }
        if (ins == (byte) 0xE2) {
            update(apdu);
            return;
        }
        require(ins == (byte) 0xCA, ISO7816.SW_INS_NOT_SUPPORTED);
        require(!apdu.isSecureMessagingCLA(), ISO7816.SW_CLA_NOT_SUPPORTED);
        if (parameter == NEXT) {
            require(state[KIND] != INVALIDATED, ISO7816.SW_DATA_INVALID);
            require(state[KIND] == RULES, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            send(apdu, false);
            return;
        }
        state[KIND] = 0;
        switch (parameter) {
            case ALL:
                buildRules();
                state[KIND] = RULES;
                send(apdu, false);
                return;
            case REFRESH:
                output[0] = (byte) 0xDF;
                output[1] = 0x20;
                output[2] = 8;
                Util.arrayCopyNonAtomic(refresh, (short) 0, output, (short) 3, (short) 8);
                startResponse((short) 11);
                send(apdu, true);
                return;
            case HASHES:
                buildHashList();
                send(apdu, true);
                return;
            case CONFIG:
                require(configAllowed, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                short size = receive(apdu);
                require(size == 7 && buffer[5] == (byte) 0xE4 && buffer[6] == 5
                        && buffer[7] == (byte) 0xE6 && buffer[8] == 3, ISO7816.SW_WRONG_DATA);
                output[0] = (byte) 0xDF;
                output[1] = 0x21;
                output[2] = 7;
                output[3] = (byte) 0xE5;
                output[4] = 5;
                output[5] = (byte) 0xE6;
                output[6] = 3;
                output[7] = 1;
                output[8] = master ? (byte) 1 : (byte) 0;
                output[9] = 0;
                startResponse((short) 10);
                // Case 4 also works with T=0, where Le is unavailable here.
                ISOException.throwIt((short) 0x610A);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void authenticate(APDU apdu, byte ins) {
        byte[] buffer = apdu.getBuffer();
        if (ins == (byte) 0x50) {
            channel.resetSecurity();
            state[SCP03] = 0;
            require(!apdu.isSecureMessagingCLA(), ISO7816.SW_CLA_NOT_SUPPORTED);
        } else {
            require(state[SCP03] == 1, ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            // C-MAC and C-MAC+C-ENC only; R-MAC/R-ENC are not negotiated.
            byte level = buffer[ISO7816.OFFSET_P1];
            require(level == 1 || level == 3, ISO7816.SW_INCORRECT_P1P2);
        }
        // GP owns reception for handshake APDUs and writes its response at
        // OFFSET_CDATA. Calling setIncomingAndReceive here would receive twice.
        short size = channel.processSecurity(apdu);
        if (ins == (byte) 0x50) {
            // INITIALIZE UPDATE: 10-byte KDD, key version, SCP identifier.
            if (size < 12 || buffer[(short) (ISO7816.OFFSET_CDATA + 11)] != 3) {
                channel.resetSecurity();
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            state[SCP03] = 1;
        }
        if (size != 0) {
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, size);
        }
    }

    private short receive(APDU apdu) {
        short received = apdu.setIncomingAndReceive();
        short size = apdu.getIncomingLength();
        require(apdu.getOffsetCdata() == ISO7816.OFFSET_CDATA
                && size <= (short) (apdu.getBuffer().length - ISO7816.OFFSET_CDATA),
                ISO7816.SW_WRONG_LENGTH);
        while (received < size) {
            short next = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + received));
            require(next > 0, ISO7816.SW_WRONG_LENGTH);
            received += next;
        }
        return size;
    }

    private void update(APDU apdu) {
        require(state[SCP03] == 1 && apdu.isSecureMessagingCLA()
                && (channel.getSecurityLevel() & (SecureChannel.AUTHENTICATED | SecureChannel.C_MAC))
                == (byte) (SecureChannel.AUTHENTICATED | SecureChannel.C_MAC),
                ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        short size = receive(apdu);
        byte[] buffer = apdu.getBuffer();
        size = (short) (channel.unwrap(buffer, (short) 0,
                (short) (ISO7816.OFFSET_CDATA + size)) - ISO7816.OFFSET_CDATA);
        short operation = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
        short slot = (short) (buffer[ISO7816.OFFSET_P2] & 0xFF);
        require(operation >= 1 && operation <= 3 && slot < SLOTS, ISO7816.SW_INCORRECT_P1P2);
        short hashLength = EMPTY;
        if (operation == 3) {
            require(size == 0, ISO7816.SW_WRONG_LENGTH);
        } else {
            require(size >= 2, ISO7816.SW_WRONG_LENGTH);
            hashLength = (short) (buffer[6] & 0xFF);
            require(buffer[5] == (byte) 0xC1 && (hashLength == 0 || hashLength == 20 || hashLength == 32)
                    && size == (short) (hashLength + 2), ISO7816.SW_WRONG_DATA);
            short existing = find(buffer, (short) 7, hashLength);
            require(existing < 0 || (operation == 2 && existing == slot), ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        require(operation != 1 || lengths[slot] == EMPTY, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        require(operation == 1 || lengths[slot] != EMPTY, (short) 0x6A88);
        if (operation == 2 && lengths[slot] == hashLength
                && Util.arrayCompare(buffer, (short) 7, hashes, (short) (slot * HASH_SIZE), hashLength) == 0) {
            return;
        }
        do {
            random.generateData(newRefresh, (short) 0, (short) 8);
        } while (Util.arrayCompare(refresh, (short) 0, newRefresh, (short) 0, (short) 8) == 0);
        // Commit a single slot and refresh tag atomically, including on power loss.
        JCSystem.beginTransaction();
        short offset = (short) (slot * HASH_SIZE);
        for (short i = 0; i < HASH_SIZE; i++) {
            hashes[(short) (offset + i)] = i < hashLength ? buffer[(short) (7 + i)] : (byte) 0;
        }
        lengths[slot] = (byte) hashLength;
        Util.arrayCopy(newRefresh, (short) 0, refresh, (short) 0, (short) 8);
        JCSystem.commitTransaction();
        state[KIND] = state[KIND] == RULES ? INVALIDATED : (short) 0;
    }

    private short find(byte[] data, short offset, short size) {
        for (short slot = 0; slot < SLOTS; slot++) {
            if (lengths[slot] == size && Util.arrayCompare(data, offset, hashes,
                    (short) (slot * HASH_SIZE), size) == 0) {
                return slot;
            }
        }
        return -1;
    }

    private void buildRules() {
        short size = 0;
        for (short slot = 0; slot < SLOTS; slot++) {
            if (lengths[slot] != EMPTY) {
                size += master ? (lengths[slot] == 0 ? (short) 13 : (short) (42 + 2 * lengths[slot]))
                        : (short) (18 + lengths[slot]);
            }
        }
        short pos = header(ALL, size);
        for (short slot = 0; slot < SLOTS; slot++) {
            if (lengths[slot] != EMPTY) {
                // Empty DeviceAppID does not grant Android Carrier Privileges.
                // Emit only the generic APDU rule for an ARA-M wildcard.
                if (!master || lengths[slot] != 0) {
                    pos = rule(pos, slot, master, master);
                }
                if (master) {
                    pos = rule(pos, slot, true, false);
                }
            }
        }
        state[POS] = 0;
        state[END] = pos;
    }

    private short rule(short pos, short slot, boolean aid, boolean carrier) {
        short size = lengths[slot];
        short refSize = (short) (size + 2 + (aid ? (carrier ? 8 : 2) : 0));
        short arSize = master ? (carrier ? (short) 13 : (short) 3) : (short) 10;
        output[pos++] = (byte) 0xE2;
        output[pos++] = (byte) (2 + refSize + 2 + arSize);
        output[pos++] = (byte) 0xE1;
        output[pos++] = (byte) refSize;
        if (aid) {
            output[pos++] = 0x4F;
            output[pos++] = carrier ? (byte) 6 : (byte) 0;
            if (carrier) {
                for (short i = 0; i < 6; i++) {
                    output[pos++] = (byte) 0xFF;
                }
            }
        }
        output[pos++] = (byte) 0xC1;
        output[pos++] = (byte) size;
        pos = Util.arrayCopyNonAtomic(hashes, (short) (slot * HASH_SIZE), output, pos, size);
        output[pos++] = (byte) 0xE3;
        output[pos++] = (byte) arSize;
        if (master) {
            output[pos++] = (byte) 0xD0;
            output[pos++] = 1;
            output[pos++] = 1;
        }
        if (!master || carrier) {
            output[pos++] = (byte) 0xDB;
            output[pos++] = 8;
            for (short i = 0; i < 8; i++) {
                output[pos++] = (i == 7 || (!master && (i == 3 || i == 5))) ? (byte) 1 : (byte) 0;
            }
        }
        return pos;
    }

    private void buildHashList() {
        short size = 0;
        for (short slot = 0; slot < SLOTS; slot++) {
            if (lengths[slot] != EMPTY) {
                size += (short) (7 + lengths[slot]);
            }
        }
        short pos = header(HASHES, size);
        for (short slot = 0; slot < SLOTS; slot++) {
            if (lengths[slot] != EMPTY) {
                output[pos++] = (byte) 0xE2;
                output[pos++] = (byte) (5 + lengths[slot]);
                output[pos++] = (byte) 0x80;
                output[pos++] = 1;
                output[pos++] = (byte) slot;
                output[pos++] = (byte) 0xC1;
                output[pos++] = lengths[slot];
                pos = Util.arrayCopyNonAtomic(hashes, (short) (slot * HASH_SIZE), output, pos, lengths[slot]);
            }
        }
        startResponse(pos);
    }

    private short header(short tag, short size) {
        short pos = Util.setShort(output, (short) 0, tag);
        if (size >= 256) {
            output[pos++] = (byte) 0x82;
            return Util.setShort(output, pos, size);
        }
        if (size >= 128) {
            output[pos++] = (byte) 0x81;
        }
        output[pos++] = (byte) size;
        return pos;
    }

    private void startResponse(short size) {
        state[POS] = 0;
        state[END] = size;
        state[KIND] = RESPONSE;
    }

    private void send(APDU apdu, boolean continuationStatus) {
        short size = apdu.setOutgoing();
        require(size > 0, ISO7816.SW_WRONG_LENGTH);
        short remaining = (short) (state[END] - state[POS]);
        if (size > 256) {
            size = 256;
        }
        if (size > remaining) {
            size = remaining;
        }
        apdu.setOutgoingLength(size);
        apdu.sendBytesLong(output, state[POS], size);
        state[POS] += size;
        remaining -= size;
        if (remaining == 0) {
            state[KIND] = 0;
        } else if (continuationStatus) {
            ISOException.throwIt((short) (0x6100 | (remaining >= 256 ? 0 : remaining)));
        }
        // GET DATA All/Next: 9000; the BER length tells Android to fetch Next.
    }

    private static void require(boolean condition, short status) {
        if (!condition) {
            ISOException.throwIt(status);
        }
    }
}
