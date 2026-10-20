package com.mekfeya.appcheckbridge;

import org.junit.Test;
import static org.junit.Assert.*;

public class BridgePolicyTest {
    @Test public void diagnosticsAreFixedLabels() {
        assertEquals("HMS_GMS_UPDATE_REQUIRED", BridgePolicy.gmsFailure(2));
        assertEquals("HMS_GMS_DISABLED", BridgePolicy.gmsFailure(3));
        assertEquals("HMS_GMS_INVALID", BridgePolicy.gmsFailure(9));
        assertEquals("HMS_GMS_UPDATING", BridgePolicy.gmsFailure(18));
        assertEquals("HMS_GMS_UNAVAILABLE", BridgePolicy.gmsFailure(12345));
        assertEquals("HMS_SIGNER_DENIED", BridgePolicy.identityFailure(
            BridgePolicy.PROJECT, BridgePolicy.APP, BridgePolicy.PACKAGE,
            false, new String[]{"untrusted"}));
        assertEquals("HMS_PROJECT_MISMATCH", BridgePolicy.identityFailure(
            "secret", BridgePolicy.APP, BridgePolicy.PACKAGE, false,
            new String[]{BridgePolicy.SIGNER}));
    }
    @Test public void flutterFlowSignerIsDevOnlyAndNotDebuggable() {
        String[] signer = {BridgePolicy.FLUTTERFLOW_DEV_SIGNER};
        assertTrue(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            BridgePolicy.PACKAGE, false, signer));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            BridgePolicy.PACKAGE, true, signer));
        assertFalse(BridgePolicy.allowed("telebusiness-25410", BridgePolicy.APP,
            BridgePolicy.PACKAGE, false, signer));
        assertFalse(BridgePolicy.allowed("production", BridgePolicy.APP,
            BridgePolicy.PACKAGE, false, signer));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, "wrong",
            BridgePolicy.PACKAGE, false, signer));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            "com.mekfeya.telecloud", false, signer));
        assertFalse(BridgePolicy.allowed(BridgePolicy.PROJECT, BridgePolicy.APP,
            BridgePolicy.PACKAGE, false,
            new String[]{BridgePolicy.SIGNER, BridgePolicy.FLUTTERFLOW_DEV_SIGNER}));
    }
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
