package com.mekfeya.appcheckbridge;

/** Deliberately Dev-only. A later reviewed promotion must explicitly add Telecloud. */
final class BridgePolicy {
    static final String PROJECT = "fintracker-dev-fa037";
    static final String APP = "1:853460861480:android:dcad031b3ecec2196b6b1d";
    static final String PACKAGE = "com.mekfeya.ethiofinance";
    static final String SIGNER =
        "21b768d7e2f0a3a895b38fbd696e86677d8b0de1a285937a2f7d84b58bc64b4c";
    // Approved FlutterFlow download signer, Development only. Not a release trust
    // anchor for Telecloud or Production; debuggable applications remain denied.
    static final String FLUTTERFLOW_DEV_SIGNER =
        "a10fe0b339079dc4fe3db033d808656eb1f55b4edd48ec4f2fbcc38b21a6b75c";

    static boolean allowed(String project, String app, String pkg,
                           boolean debuggable, String[] signers) {
        if (!PROJECT.equals(project) || !APP.equals(app) ||
                !PACKAGE.equals(pkg) || debuggable ||
                signers == null || signers.length != 1) return false;
        return SIGNER.equals(signers[0]) || FLUTTERFLOW_DEV_SIGNER.equals(signers[0]);
    }

    static boolean validTokenShape(String token, long expires, long now) {
        // This is transport validation, NOT a replacement for server verification.
        return token != null && token.length() <= 16000 &&
            token.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+") &&
            expires > now + 1000 && expires <= now + 30 * 60 * 1000L;
    }
}
