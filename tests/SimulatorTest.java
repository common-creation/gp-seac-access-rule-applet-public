/*
 * Copyright 2025-2026 COMMON CREATION, Co., Ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import org.globalplatform.GPSystem;

public final class SimulatorTest {
    static class Card implements ProtocolTest.Transport {
        final Simulator simulator=new Simulator();
        final AID aid;
        Card(boolean master,byte[] parameters) {
            byte[] id=ProtocolTest.hex(master?"A00000015141434C00":"A00000015144414300");
            aid=new AID(id,(short)0,(byte)id.length);
            byte[] install=ProtocolTest.concat(new byte[]{(byte)id.length},id,new byte[]{0,(byte)parameters.length},parameters);
            simulator.installApplet(aid,master?com.common_creation.applet.gp_ara_m.ARAMApplet.class
                    :com.common_creation.applet.gp_ara_d.ARADApplet.class,install,(short)0,(byte)install.length);
        }
        public byte[] raw(byte[] c){return simulator.transmitCommand(c);}
        public void select(){ProtocolTest.check(simulator.selectApplet(aid),"select");}
        public void reset(){simulator.reset();}
        public void authenticate(boolean encrypt){
            ProtocolTest.expect(raw(ProtocolTest.hex("8050020008000000000000000000")),0x9000);
            ProtocolTest.expect(raw(ProtocolTest.command(0x84,0x82,encrypt?3:1,0,new byte[16])),0x9000);
        }
        public byte[] secure(byte[] command){
            byte[] c;
            if(command.length==4)c=ProtocolTest.concat(command,new byte[]{8},ProtocolTest.filled(8,0xA5));
            else{c=ProtocolTest.concat(command,ProtocolTest.filled(8,0xA5));c[4]+=8;}
            c[0]=(byte)0x84;return raw(c);
        }
    }
    public static void main(String[] args)throws Exception {
        byte[] parameters=ProtocolTest.concat(ProtocolTest.tlv(0xC1,ProtocolTest.H1),ProtocolTest.tlv(0xC1,ProtocolTest.H2));
        for(boolean master:new boolean[]{false,true}){
            Card c=new Card(master,parameters);ProtocolTest.run(c,master);
            c.select();GPSystem.CHANNEL.protocol=2;
            ProtocolTest.expect(c.raw(ProtocolTest.hex("8050010008000000000000000000")),0x6982);
            GPSystem.CHANNEL.protocol=3;c.authenticate(false);GPSystem.CHANNEL.rejectMac=true;
            ProtocolTest.expect(ProtocolTest.update(c,3,0,new byte[0]),0x6982);
            ProtocolTest.check(ProtocolTest.hashes(c).size()==2,"bad MAC preserves data");
            c.simulator.resetRuntime();
        }
        for(byte[] bad:new byte[][]{ProtocolTest.hex("C100C100"),ProtocolTest.hex("C11401"),ProtocolTest.hex("C20100"),
                ProtocolTest.concat(parameters,ProtocolTest.tlv(0xC1,ProtocolTest.H1)),ProtocolTest.hex("C1")}){
            boolean rejected=false;try{Card c=new Card(false,bad);c.simulator.resetRuntime();}catch(Exception e){rejected=true;}
            ProtocolTest.check(rejected,"reject malformed/duplicate installation");
        }
        for(boolean master:new boolean[]{false,true}) {
            Card empty=new Card(master,new byte[0]);empty.select();
            ProtocolTest.check(ProtocolTest.hashes(empty).isEmpty(),"empty installation");
            ProtocolTest.check(java.util.Arrays.equals(ProtocolTest.rules(empty,0),ProtocolTest.hex("FF4000")),"no default allow rule");
            empty.simulator.resetRuntime();
            Card wildcard=new Card(master,ProtocolTest.hex("C100"));wildcard.select();
            java.util.Map<Integer,byte[]> wildcardRules=new java.util.TreeMap<>();
            wildcardRules.put(0,new byte[0]);
            ProtocolTest.check(ProtocolTest.hashes(wildcard).get(0).length==0,"wildcard installation");
            ProtocolTest.validateRules(wildcard,master,wildcardRules,0);
            wildcard.simulator.resetRuntime();
            byte[] many=new byte[0];
            java.util.Map<Integer,byte[]> expected=new java.util.TreeMap<>();
            for(int slot=0;slot<5;slot++) {
                byte[] hash=ProtocolTest.filled(32,0x90+slot);expected.put(slot,hash);
                many=ProtocolTest.concat(many,ProtocolTest.tlv(0xC1,hash));
            }
            Card longInstall=new Card(master,many);longInstall.select();
            ProtocolTest.check(ProtocolTest.hashes(longInstall).size()==5,"unsigned installation length > 127");
            ProtocolTest.validateRules(longInstall,master,expected,0);
            longInstall.simulator.resetRuntime();
        }
        System.out.println("PASS: "+ProtocolTest.assertions+" assertions (simulated OS security, not SCP03 cryptography)");
    }
}
