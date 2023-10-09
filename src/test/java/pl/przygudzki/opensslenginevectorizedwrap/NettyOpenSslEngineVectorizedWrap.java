package pl.przygudzki.opensslenginevectorizedwrap;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.OpenSslEngine;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NettyOpenSslEngineVectorizedWrap {

    private static final String TLSv1_3 = "TLSv1.3";
    private static final String SERVER_KEYSTORE_PATH = "/server.keystore";
    private static final String SERVER_TRUSTSTORE_PATH = "/server.truststore";
    private static final String CLIENT_KEYSTORE_PATH = "/client.keystore";
    private static final String CLIENT_TRUSTSTORE_PATH = "/client.truststore";
    private static final String STORE_PASS = "password";
    private static final String KEY_PASS = "password";
    private static final String PKCS12 = "PKCS12";

    private final Random random = new Random();

    private final KeyManagerFactory serverKeyManagerFactory = prepareKeyManagerFactory(SERVER_KEYSTORE_PATH);
    private final TrustManagerFactory serverTrustManagerFactory = prepareTrustManagerFactory(SERVER_TRUSTSTORE_PATH);
    private final KeyManagerFactory clientKeyManagerFactory = prepareKeyManagerFactory(CLIENT_KEYSTORE_PATH);
    private final TrustManagerFactory clientTrustManagerFactory = prepareTrustManagerFactory(CLIENT_TRUSTSTORE_PATH);
    private final ByteBuffer emptyBuffer = ByteBuffer.allocate(0);
    private final ByteBuffer netBufferAlpha = ByteBuffer.allocate(32 * 1024);
    private final ByteBuffer netBufferBravo = ByteBuffer.allocate(32 * 1024);
    private final ByteBuffer serverBuffer = ByteBuffer.allocate(32 * 1024);
    private final ByteBuffer clientBuffer = ByteBuffer.allocate(32 * 1024);

    @Test
    public void testJdkImpl() throws Exception {
        SSLEngine serverSslEngine = prepareServerSslEngine(SslProvider.JDK);
        SSLEngine clientSslEngine = prepareClientSslEngine(SslProvider.JDK);
        assertFalse(serverSslEngine instanceof OpenSslEngine);
        assertFalse(clientSslEngine instanceof OpenSslEngine);

        testScenario(serverSslEngine, clientSslEngine);
    }

    @Test
    public void testOpenSslImpl() throws Exception {
        SSLEngine serverSslEngine = prepareServerSslEngine(SslProvider.OPENSSL);
        SSLEngine clientSslEngine = prepareClientSslEngine(SslProvider.OPENSSL);
        assertTrue(serverSslEngine instanceof OpenSslEngine);
        assertTrue(clientSslEngine instanceof OpenSslEngine);

        testScenario(serverSslEngine, clientSslEngine);
    }

    private void testScenario(SSLEngine serverSslEngine, SSLEngine clientSslEngine) throws Exception {
        completeHandshake(serverSslEngine, clientSslEngine);

        ByteBuffer[] buffVector = preparePayload();

        clientSslEngine.wrap(buffVector, 0, buffVector.length, netBufferAlpha);

        for (ByteBuffer buffer : buffVector) {
            assertFalse(buffer.hasRemaining());
        }
    }

    private ByteBuffer[] preparePayload() {
        ByteBuffer[] buffVector = new ByteBuffer[2];
        for (int i = 0; i < buffVector.length; i++) {
            byte[] bytes = new byte[1024];
            random.nextBytes(bytes);
            buffVector[i] = ByteBuffer.wrap(bytes);
        }
        return buffVector;
    }

    private void completeHandshake(SSLEngine serverSslEngine, SSLEngine clientSslEngine) throws SSLException {
        clientSslEngine.beginHandshake();
        while (
                !(serverSslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING &&
                        clientSslEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
        ) {
            performHandshakeExchange(clientSslEngine, serverSslEngine, netBufferAlpha, serverBuffer);
            performHandshakeExchange(serverSslEngine, clientSslEngine, netBufferBravo, clientBuffer);
        }

        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, serverSslEngine.getHandshakeStatus());
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, clientSslEngine.getHandshakeStatus());
    }

    private SSLEngine prepareServerSslEngine(SslProvider sslProvider) throws SSLException {
        return SslContextBuilder.forServer(serverKeyManagerFactory)
                .trustManager(serverTrustManagerFactory)
                .sslProvider(sslProvider)
                .protocols(TLSv1_3)
                .build()
                .newEngine(ByteBufAllocator.DEFAULT);
    }

    private SSLEngine prepareClientSslEngine(SslProvider sslProvider) throws SSLException {
        return SslContextBuilder.forClient()
                .keyManager(clientKeyManagerFactory)
                .trustManager(clientTrustManagerFactory)
                .sslProvider(sslProvider)
                .protocols(TLSv1_3)
                .build()
                .newEngine(ByteBufAllocator.DEFAULT);
    }

    private KeyManagerFactory prepareKeyManagerFactory(String keystorePath) {
        try {
            var keystoreFile = NettyOpenSslEngineVectorizedWrap.class.getResource(keystorePath).getFile();
            return createKeyManagerFactory(keystoreFile, STORE_PASS, KEY_PASS, PKCS12);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private TrustManagerFactory prepareTrustManagerFactory(String truststorePath) {
        try {
            var truststoreFile = NettyOpenSslEngineVectorizedWrap.class.getResource(truststorePath).getFile();
            return createTrustManagerFactory(truststoreFile, STORE_PASS, PKCS12);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private void performHandshakeExchange(
            SSLEngine writingSslEngine, SSLEngine readingSslEngine,
            ByteBuffer netBuffer, ByteBuffer appBuffer
    ) throws SSLException {
        writingSslEngine.wrap(emptyBuffer, netBuffer);
        netBuffer.flip();
        readingSslEngine.unwrap(netBuffer, appBuffer);
        netBuffer.compact();
        Runnable delegatedTask = readingSslEngine.getDelegatedTask();
        if (delegatedTask != null) {
            delegatedTask.run();
        }
    }

    public static KeyManagerFactory createKeyManagerFactory(
            String filepath, String keystorePassword, String keyPassword, String keystoreType
    ) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try (InputStream keyStoreIS = Files.newInputStream(Paths.get(filepath))) {
            keyStore.load(keyStoreIS, keystorePassword.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword.toCharArray());
        return kmf;
    }

    public static TrustManagerFactory createTrustManagerFactory(
            String filepath, String keystorePassword, String truststoreType
    ) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(truststoreType);
        try (InputStream trustStoreIS = Files.newInputStream(Paths.get(filepath))) {
            trustStore.load(trustStoreIS, keystorePassword.toCharArray());
        }
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        return trustFactory;
    }
}
