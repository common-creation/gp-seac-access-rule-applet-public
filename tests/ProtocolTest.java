/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

import java.io.ByteArrayOutputStream;
import java.util.*;

/** Protocol assertions shared by the ARA-M and ARA-D simulator tests. */
public final class ProtocolTest {
    interface Transport {
        byte[] raw(byte[] command) throws Exception;
        byte[] secure(byte[] command) throws Exception;
        void select() throws Exception;
        void authenticate(boolean encrypt) throws Exception;
        void reset() throws Exception;
    }
    static int assertions;
    static final byte[] H1 = filled(20, 0x11);
    static final byte[] H2 = filled(32, 0x22);
    static byte[] filled(int size, int value) {
        byte[] b = new byte[size]; Arrays.fill(b, (byte) value); return b;
    }
    static byte[] hex(String value) { return java.util.HexFormat.of().parseHex(value); }
    static String hex(byte[] value) { return java.util.HexFormat.of().withUpperCase().formatHex(value); }
    static void check(boolean ok, String message) {
        assertions++; if (!ok) throw new AssertionError(message);
    }
    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] part : parts) b.write(part, 0, part.length);
        return b.toByteArray();
    }
    static byte[] tlv(int tag, byte[] value) {
        byte[] t = tag > 255 ? new byte[]{(byte)(tag >> 8), (byte)tag} : new byte[]{(byte)tag};
        byte[] l = value.length < 128 ? new byte[]{(byte)value.length}
                : value.length < 256 ? new byte[]{(byte)0x81, (byte)value.length}
                : new byte[]{(byte)0x82, (byte)(value.length >> 8), (byte)value.length};
        return concat(t, l, value);
    }
    static byte[] command(int cla, int ins, int p1, int p2, byte[] data) {
        if (data.length == 0) return new byte[]{(byte)cla,(byte)ins,(byte)p1,(byte)p2};
        return concat(new byte[]{(byte)cla,(byte)ins,(byte)p1,(byte)p2,(byte)data.length}, data);
    }
    static int sw(byte[] response) {
        return ((response[response.length-2]&255)<<8) | (response[response.length-1]&255);
    }
    static byte[] expect(byte[] r, int status) {
        check(sw(r) == status, String.format("Expected %04X, got %s", status, hex(r)));
        return Arrays.copyOf(r,r.length-2);
    }
    static byte[] read(Transport t, String apdu) throws Exception {
        byte[] r=t.raw(hex(apdu)); ByteArrayOutputStream out=new ByteArrayOutputStream();
        while ((sw(r)&0xff00)==0x6100) {
            out.write(r,0,r.length-2);
            r=t.raw(new byte[]{0,(byte)0xc0,0,0,(byte)sw(r)});
        }
        byte[] last=expect(r,0x9000); out.write(last); return out.toByteArray();
    }
    static byte[] value(byte[] bytes, int tag) {
        int pos=tag>255?2:1;
        check(bytes.length>pos && (tag>255 ? ((bytes[0]&255)<<8)|(bytes[1]&255) : bytes[0]&255)==tag,"TLV tag");
        int length=bytes[pos++]&255;
        if(length>=128) {
            int count=length&127;check(count>0&&count<=2,"BER length width");length=0;
            while(count-->0)length=(length<<8)|(bytes[pos++]&255);
        }
        check(bytes.length==pos+length,"BER total length");
        return Arrays.copyOfRange(bytes,pos,bytes.length);
    }
    static List<byte[]> children(byte[] data) {
        List<byte[]> result=new ArrayList<>();int pos=0;
        while(pos<data.length) {
            int start=pos++;int length=data[pos++]&255;
            check(length<128&&pos+length<=data.length,"child TLV bounds");
            pos+=length;result.add(Arrays.copyOfRange(data,start,pos));
        }
        return result;
    }
    static Map<Integer,byte[]> hashes(Transport t) throws Exception {
        Map<Integer,byte[]> result=new TreeMap<>();
        for(byte[] entry:children(value(read(t,"80CADF2200"),0xDF22))) {
            List<byte[]> fields=children(value(entry,0xE2));
            check(fields.size()==2,"hash entry fields");
            int slot=value(fields.get(0),0x80)[0]&255;
            check(!result.containsKey(slot),"unique slot");
            result.put(slot,value(fields.get(1),0xC1));
        }
        return result;
    }
    static byte[] rules(Transport t, int le) throws Exception {
        byte[] r=expect(t.raw(new byte[]{(byte)0x80,(byte)0xca,(byte)0xff,0x40,(byte)le}),0x9000);
        int pos=2;int length=r[pos++]&255;
        if(length>=128){int n=length&127;length=0;while(n-->0)length=(length<<8)|(r[pos++]&255);}
        int total=pos+length;
        while(r.length<total) {
            byte[] next=expect(t.raw(new byte[]{(byte)0x80,(byte)0xca,(byte)0xff,0x60,(byte)le}),0x9000);
            check(next.length>0,"Next advances");r=concat(r,next);
        }
        value(r,0xFF40);return r;
    }
    static void validateRules(Transport t, boolean master, Map<Integer,byte[]> expected, int le) throws Exception {
        List<byte[]> entries=children(value(rules(t,le),0xFF40));
        int count=0;for(byte[] hash:expected.values())count+=master&&hash.length!=0?2:1;
        check(entries.size()==count,"rule count");
        int i=0;
        for(byte[] hash:expected.values()) {
            for(int k=0;k<(master&&hash.length!=0?2:1);k++) {
                boolean carrier=master&&hash.length!=0&&k==0;
                List<byte[]> fields=children(value(entries.get(i++),0xE2));
                check(fields.size()==2,"REF and AR enclosed in E2");
                List<byte[]> ref=children(value(fields.get(0),0xE1));
                if(master)check(Arrays.equals(value(ref.get(0),0x4F),carrier?filled(6,255):new byte[0]),"target AID");
                check(Arrays.equals(value(ref.get(master?1:0),0xC1),hash),"certificate hash");
                byte[] ar=value(fields.get(1),0xE3);
                check(Arrays.equals(ar,hex(master?(carrier?"D00101DB080000000000000001":"D00101")
                        :"DB080000000100010001")),"permissions");
            }
        }
    }
    static byte[] update(Transport t,int op,int slot,byte[] hash) throws Exception {
        return t.secure(command(0x80,0xE2,op,slot,op==3?new byte[0]:tlv(0xC1,hash)));
    }
    static void run(Transport t, boolean master) throws Exception {
        t.select();
        expect(t.raw(hex("80CAFF6000")),0x6985);
        expect(t.raw(hex("00C0000000")),0x6985);
        expect(t.raw(hex("00CAFF4000")),0x6E00);
        expect(t.raw(command(0x80,0xE2,3,0,new byte[0])),0x6982);
        expect(t.raw(command(0x84,0xE2,3,0,new byte[8])),0x6982);
        t.select();
        byte[] config=read(t,"80CADF2107E405E60301010000");
        check(Arrays.equals(config,hex(master?"DF2107E505E603010100":"DF2107E505E603010000")),"config");
        expect(t.raw(hex("80CADF2107E405E60301010000")),0x6985);
        Map<Integer,byte[]> expected=new TreeMap<>(); expected.put(0,H1);expected.put(1,H2);
        check(hashes(t).size()==2,"multiple install hashes");
        validateRules(t,master,expected,0);
        byte[] initialRefresh=read(t,"80CADF2000");
        t.authenticate(false);
        expect(t.raw(command(0x80,0xE2,3,0,new byte[0])),0x6982);
        expect(update(t,1,2,H1),0x6985);
        expect(update(t,1,16,H1),0x6A86);
        expect(update(t,2,15,H1),0x6985); // duplicate is detected before slot existence
        expect(update(t,3,15,new byte[0]),0x6A88);
        expect(update(t,1,2,filled(19,0x33)),0x6A80);
        check(Arrays.equals(initialRefresh,read(t,"80CADF2000")),"failed commands preserve refresh");
        byte[] h3=filled(20,0x33);
        expect(update(t,1,2,h3),0x9000);expected.put(2,h3);
        byte[] addedRefresh=read(t,"80CADF2000");
        check(!Arrays.equals(initialRefresh,addedRefresh),"add changes refresh");
        expect(update(t,2,2,h3),0x9000);
        check(Arrays.equals(addedRefresh,read(t,"80CADF2000")),"no-op preserves refresh");
        expect(update(t,1,2,filled(32,0x44)),0x6985);
        expect(update(t,2,2,filled(32,0x44)),0x9000);expected.put(2,filled(32,0x44));
        check(!Arrays.equals(addedRefresh,read(t,"80CADF2000")),"replace changes refresh");
        validateRules(t,master,expected,17);
        t.reset();t.select();
        check(Arrays.equals(hashes(t).get(2),filled(32,0x44)),"persistent hashes");
        expect(t.raw(command(0x84,0xE2,3,2,new byte[8])),0x6982);
        t.authenticate(true);
        for(int slot=3;slot<16;slot++) {
            byte[] h=filled(32,0x80+slot);expect(update(t,1,slot,h),0x9000);expected.put(slot,h);
        }
        check(hashes(t).size()==16,"full capacity and GET RESPONSE chaining");
        validateRules(t,master,expected,0);
        // A successful update during an unfinished rules read invalidates Next.
        expect(t.raw(hex("80CAFF4010")),0x9000);
        expect(update(t,3,2,new byte[0]),0x9000);expected.remove(2);
        expect(t.raw(hex("80CAFF6000")),0x6984);
        validateRules(t,master,expected,31);
        check(Arrays.equals(hashes(t).get(15),expected.get(15)),"deletion preserves slot numbers");
        byte[] beforeDelete=read(t,"80CADF2000");
        expect(update(t,3,15,new byte[0]),0x9000);expected.remove(15);
        check(!Arrays.equals(beforeDelete,read(t,"80CADF2000")),"delete changes refresh");
        for(int slot:new ArrayList<>(expected.keySet()))expect(update(t,3,slot,new byte[0]),0x9000);
        check(hashes(t).isEmpty(),"empty list");
        check(Arrays.equals(rules(t,0),hex("FF4000")),"empty rules deny all");
        // Explicit wildcard is a present slot, not an empty allow-list or a zero hash.
        byte[] noHash=new byte[0];expected.clear();
        byte[] beforeWildcard=read(t,"80CADF2000");
        expect(update(t,1,5,noHash),0x9000);expected.put(5,noHash);
        check(hashes(t).containsKey(5)&&hashes(t).get(5).length==0,"wildcard listed as C100");
        validateRules(t,master,expected,0);
        byte[] wildcardRefresh=read(t,"80CADF2000");
        check(!Arrays.equals(beforeWildcard,wildcardRefresh),"wildcard add changes refresh");
        expect(update(t,1,6,noHash),0x6985);
        expect(update(t,2,5,noHash),0x9000);
        check(Arrays.equals(wildcardRefresh,read(t,"80CADF2000")),"wildcard no-op preserves refresh");
        expect(update(t,1,6,filled(20,0)),0x9000);expected.put(6,filled(20,0));
        validateRules(t,master,expected,0);
        t.reset();t.select();
        check(hashes(t).containsKey(5)&&hashes(t).get(5).length==0,"wildcard persists after reset");
        expect(t.raw(command(0x80,0xE2,3,5,noHash)),0x6982);
        t.authenticate(true);
        expect(update(t,2,5,H1),0x9000);expected.put(5,H1);
        validateRules(t,master,expected,0);
        expect(update(t,2,5,noHash),0x9000);expected.put(5,noHash);
        validateRules(t,master,expected,0);
        expect(update(t,3,5,noHash),0x9000);expected.remove(5);
        validateRules(t,master,expected,0);
        expect(update(t,3,5,noHash),0x6A88);
        expect(update(t,3,6,noHash),0x9000);
        check(hashes(t).isEmpty(),"wildcard removed without leaving an occupied slot");
        check(Arrays.equals(rules(t,0),hex("FF4000")),"removing all entries restores deny-all");
        // Restore the installation fixtures.
        expect(update(t,1,0,H1),0x9000);expect(update(t,1,1,H2),0x9000);
        t.select();expect(t.raw(command(0x84,0xE2,3,0,new byte[8])),0x6982);
        t.authenticate(false);
        byte[] beforeTamper=read(t,"80CADF2000");
        int tamperedStatus=sw(t.raw(command(0x84,0xE2,3,0,new byte[8])));
        check(tamperedStatus==0x6982||tamperedStatus==0x6985||tamperedStatus==0x6988,"forged MAC rejected by card OS");
        check(hashes(t).size()==2,"forged MAC does not delete data");
        check(Arrays.equals(beforeTamper,read(t,"80CADF2000")),"forged MAC preserves refresh");
        expect(update(t,3,0,new byte[0]),0x6982);
        System.out.println((master?"ARA-M":"ARA-D")+": protocol checks passed");
    }
}
