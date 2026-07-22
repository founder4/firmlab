/**
 * Frida TLS-unpinning template (Phase 6.3, design §8). When a device's app pins TLS, the OTA can't be decrypted
 * through the capture proxy — the honest ceiling is `blocked_by_pinning`. Unpinning is OPERATOR-SIDE and off-box:
 * you run this on YOUR rooted phone/emulator against YOUR app so it accepts FirmLab's CA, and the OTA becomes
 * visible. FirmLab never runs it — it only ships the template and points you at it. Served verbatim from
 * `GET /api/capture/frida-unpin`.
 */
export const FRIDA_UNPIN = String.raw`/*
 * FirmLab — universal Android TLS-unpinning helper (Frida).
 * Run on a ROOTED phone / emulator to defeat certificate pinning so a vendor app accepts FirmLab's CA and its
 * OTA download becomes visible to the capture proxy. This is operator-side (your device, your app).
 *
 *   frida -U -f <app.package.name> -l firmlab-unpin.js --no-pause
 *
 * Covers the common Android pinning points; extend per-app as needed.
 */
setTimeout(function () {
  Java.perform(function () {
    // 1. Replace the app's TrustManager with an all-trusting one at SSLContext.init.
    try {
      var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext = Java.use('javax.net.ssl.SSLContext');
      var TrustManager = Java.registerClass({
        name: 'com.firmlab.TrustAll',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function () {},
          checkServerTrusted: function () {},
          getAcceptedIssuers: function () { return []; },
        },
      });
      var init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom',
      );
      init.implementation = function (km, tm, sr) {
        init.call(this, km, [TrustManager.$new()], sr);
      };
      console.log('[firmlab] SSLContext TrustManager hooked');
    } catch (e) { console.log('[firmlab] SSLContext hook skipped: ' + e); }

    // 2. OkHttp3 CertificatePinner.check — no-op.
    try {
      var CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
      console.log('[firmlab] OkHttp CertificatePinner hooked');
    } catch (e) { console.log('[firmlab] OkHttp hook skipped: ' + e); }

    // 3. Android N+ TrustManagerImpl.verifyChain — return the chain untouched.
    try {
      var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TrustManagerImpl.verifyChain.implementation = function (chain, authType, host, clientAuth, ocsp, tls) {
        return chain;
      };
      console.log('[firmlab] TrustManagerImpl.verifyChain hooked');
    } catch (e) { console.log('[firmlab] Conscrypt hook skipped: ' + e); }
  });
}, 0);
`;
