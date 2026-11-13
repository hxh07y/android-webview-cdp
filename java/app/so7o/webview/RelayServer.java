package app.so7o.webview;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Token-authenticated loopback relay for the WebView DevTools socket. */
public class RelayServer {
    private static final String TAG = "So7oWebViewRelay";
    public static final int PORT = 9334;
    private static final int MAX_HEADER_BYTES = 16 * 1024;
    private static boolean started = false;
    private static volatile String authToken;
    private volatile boolean running;

    public static void setAuthToken(String token) {
        authToken = token;
    }

    public synchronized void start() {
        if (started) {
            Log.i(TAG, "relay already running on 127.0.0.1:" + PORT);
            return;
        }
        started = true;
        running = true;
        Thread acceptor = new Thread(new Runnable() {
            @Override public void run() { acceptLoop(); }
        }, "so7o-relay-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    private void acceptLoop() {
        ServerSocket server = null;
        try {
            server = new ServerSocket(PORT, 8, InetAddress.getByName("127.0.0.1"));
            Log.i(TAG, "authenticated relay listening on 127.0.0.1:" + PORT);
            while (running) {
                final Socket client = server.accept();
                Thread conn = new Thread(new Runnable() {
                    @Override public void run() { pipe(client); }
                }, "so7o-relay-conn");
                conn.setDaemon(true);
                conn.start();
            }
        } catch (IOException e) {
            Log.e(TAG, "relay unavailable: " + e.getMessage());
            started = false;
        } finally {
            closeQuietly(server);
        }
    }

    private void pipe(final Socket client) {
        LocalSocket local = new LocalSocket();
        try {
            client.setTcpNoDelay(true);
            client.setSoTimeout(5000);
            final BufferedInputStream clientIn =
                    new BufferedInputStream(client.getInputStream());
            byte[] headers = readHeaders(clientIn);

            // Do not connect to the privileged abstract DevTools socket until
            // the HTTP request (including a WebSocket upgrade) is authenticated.
            if (!isAuthorized(headers)) {
                OutputStream rejected = client.getOutputStream();
                rejected.write(("HTTP/1.1 401 Unauthorized\r\n"
                        + "Connection: close\r\n"
                        + "Content-Length: 0\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                rejected.flush();
                return;
            }

            client.setSoTimeout(0);
            local.connect(new LocalSocketAddress(devtoolsSocketName(),
                    LocalSocketAddress.Namespace.ABSTRACT));
            final OutputStream clientOut = client.getOutputStream();
            final InputStream localIn = local.getInputStream();
            final OutputStream localOut = local.getOutputStream();

            localOut.write(headers);
            localOut.flush();
            Thread back = new Thread(new Runnable() {
                @Override public void run() { pump(localIn, clientOut, client); }
            }, "so7o-relay-back");
            back.setDaemon(true);
            back.start();
            pump(clientIn, localOut, local);
        } catch (IOException e) {
            Log.w(TAG, "connection dropped: " + e.getMessage());
        } finally {
            closeQuietly(client);
            closeQuietly(local);
        }
    }

    private byte[] readHeaders(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int matched = 0;
        while (out.size() < MAX_HEADER_BYTES) {
            int value = in.read();
            if (value < 0) throw new IOException("incomplete HTTP headers");
            out.write(value);
            if (value == '\r') matched = (matched == 2) ? 3 : 1;
            else if (value == '\n') {
                if (matched == 1) matched = 2;
                else if (matched == 3) matched = 4;
                else matched = 0;
            } else matched = 0;
            if (matched == 4) return out.toByteArray();
        }
        throw new IOException("HTTP headers too large");
    }

    private boolean isAuthorized(byte[] rawHeaders) {
        String expected = authToken;
        if (expected == null || !expected.matches("[0-9a-fA-F]{64}")) return false;
        String headers = new String(rawHeaders, StandardCharsets.ISO_8859_1);
        int lineEnd = headers.indexOf("\r\n");
        if (lineEnd <= 0) return false;
        String[] request = headers.substring(0, lineEnd).split(" ");
        if (request.length < 2) return false;
        String target = request[1];
        int queryStart = target.indexOf('?');
        if (queryStart < 0) return false;

        String supplied = null;
        for (String param : target.substring(queryStart + 1).split("&")) {
            int equals = param.indexOf('=');
            if (equals < 0 || !"token".equals(param.substring(0, equals))) continue;
            if (supplied != null) return false;
            supplied = param.substring(equals + 1);
        }
        if (supplied == null || !supplied.matches("[0-9a-fA-F]{64}")) return false;
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                supplied.getBytes(StandardCharsets.US_ASCII));
    }

    private void pump(InputStream in, OutputStream out, Object closeOnEnd) {
        byte[] buf = new byte[16 * 1024];
        try {
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException e) {
            // normal end of stream / client vanished
        } finally {
            if (closeOnEnd instanceof Socket) closeQuietly((Socket) closeOnEnd);
            else closeQuietly((LocalSocket) closeOnEnd);
        }
    }

    private static String devtoolsSocketName() {
        return "webview_devtools_remote_" + android.os.Process.myPid();
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException ignored) {}
    }
}
