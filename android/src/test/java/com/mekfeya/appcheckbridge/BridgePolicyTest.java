package com.mekfeya.appcheckbridge;

import org.junit.Test;
import static org.junit.Assert.*;

public class BridgePolicyTest {
    @Test public void releaseIdentityOnly() {
        assertTrue(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            BridgePolicy.PACKAGE, false, new String[]{BridgePolicy.SIGNER}));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            BridgePolicy.PACKAGE, true, new String[]{BridgePolicy.SIGNER}));
        assertFalse(BridgePolicy.allowed("telebusiness-25410", BridgePolicy.APP,
            BridgePolicy.PACKAGE, false, new String[]{BridgePolicy.SIGNER}));
        assertFalse(BridgePolicy.allowed("production", BridgePolicy.APP,
            BridgePolicy.PACKAGE, false, new String[]{BridgePolicy.SIGNER}));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, "wrong",
            BridgePolicy.PACKAGE, false, new String[]{BridgePolicy.SIGNER}));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            "com.mekfeya.telecloud", false, new String[]{BridgePolicy.SIGNER}));
    }
    @Test public void rejectDebugOrExtraSigners() {
        for (String[] signers : new String[][]{ {}, {"e466"}, {"a10f"},
                {BridgePolicy.SIGNER, "extra"} }) {
            assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
                BridgePolicy.PACKAGE, false, signers));
        }
    }
    @Test public void expiryAndMalformedTokenRejected() {
        assertTrue(BridgePolicy.validTokenShape("header.payload.signature", 1801000, 1000));
        assertFalse(BridgePolicy.validTokenShape("header.payload.signature", 1801001, 1000));
        assertFalse(BridgePolicy.validTokenShape("header.payload.signature", 1000, 1000));
        assertFalse(BridgePolicy.validTokenShape("header.payload.signature", 2000, 1000));
        assertFalse(BridgePolicy.validTokenShape("not-a-token", 3000, 1000));
        assertFalse(BridgePolicy.validTokenShape("a.b.c\n", 3000, 1000));
    }
}
