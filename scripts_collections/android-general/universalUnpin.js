Java.perform(function () {
    console.log('\n[.] Cert Pinning Bypass');

    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    console.log('[+] Creating a TrustyTrustManager that trusts everything...');
    // Create a TrustManager that trusts everything
    var TrustyTrustManager = Java.registerClass({
        name: 'com.example.TrustyTrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () {
                return [];
            }
        }
    });

    console.log('[+] Our TrustyTrustManagers is ready, ...');
    console.log('[+] Hijacking SSLContext methods now...');
    console.log('[-] Waiting for the app to invoke SSLContext.init()...');

    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (a, b, c) {
        console.log('[o] App invoked SSLContext.init()...');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').call(this, a, [TrustyTrustManager.$new()], c);
        console.log('[+] SSLContext initialized with our custom TrustManager!');
    };

    // TrustManagerImpl
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    try {
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Intercepted TrustManagerImpl for host: ' + host);
            return untrustedChain;
        }

        console.log('[+] Setup TrustManagerImpl pinning');
    } catch (err) {
        console.log('[!] Unable to hook into TrustManagerImpl')
    }

    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    var Arrays = Java.use('java.util.Arrays');
    TrustManagerImpl.checkTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String', 'boolean').implementation = function(chain, type, host, b) {
        console.log('Ignoring trust check for host: ' + host);
        return Arrays.asList(chain);
    };
});