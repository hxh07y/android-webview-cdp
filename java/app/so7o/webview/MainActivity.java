package app.so7o.webview;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import android.widget.TextView;

import java.security.SecureRandom;

/**
 * Minimal WebView shell whose only trick is: remote debugging is on, so the
 * page can be driven over the Chrome DevTools Protocol from Termux.
 *
 * The DevTools server listens on the abstract unix socket
 *   webview_devtools_remote_<pid>
 * which cannot be reached from another app (SELinux), so the client side is
 * `adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>` (see
 * cdp-webview.sh).
 */
public class MainActivity extends Activity {

    private static final String TAG = "So7oWebView";
    private WebView web;

    @Override
    protected void onCreate(Bundle state) {
        // Must run before any WebView is constructed. Global to the process.
        WebView.setWebContentsDebuggingEnabled(true);
        final int pid = android.os.Process.myPid();
        Log.i(TAG, "devtools socket = webview_devtools_remote_" + pid);

        super.onCreate(state);

        // Freeze-exempt while backgrounded (see KeepAliveService) — without this
        // the DevTools socket stops accepting once the app leaves the foreground.
        startForegroundService(new Intent(this, KeepAliveService.class));

        // Per-install token is stored in app-private preferences and shown only
        // in a native dialog, never through the page's JavaScript bridge.
        final String cdpToken = getOrCreateCdpToken();
        RelayServer.setAuthToken(cdpToken);
        showCdpTokenDialog(cdpToken);

        web = new WebView(this);
        setContentView(web, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        web.setWebViewClient(new WebViewClient());
        web.addJavascriptInterface(new Bridge(), "so7o");
        web.loadUrl("file:///android_asset/index.html");

        // Publish the DevTools socket on authenticated loopback only.
        new RelayServer().start();
    }

    private String getOrCreateCdpToken() {
        SharedPreferences prefs = getSharedPreferences("cdp_auth", MODE_PRIVATE);
        String token = prefs.getString("token", null);
        if (token != null && token.matches("[0-9a-fA-F]{64}")) return token;
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder hex = new StringBuilder(64);
        for (byte b : bytes) hex.append(String.format(java.util.Locale.US, "%02x", b & 0xff));
        token = hex.toString();
        prefs.edit().putString("token", token).apply();
        return token;
    }

    private void showCdpTokenDialog(final String token) {
        TextView tokenView = new TextView(this);
        tokenView.setText("Copy this private key into Termux using ./cdp-webview.sh auth. "
                + "The key is required by CDP clients and is not shared with web pages.\n\n"
                + token);
        tokenView.setTextIsSelectable(true);
        tokenView.setPadding(48, 24, 48, 24);
        tokenView.setTextSize(14);
        new AlertDialog.Builder(this)
                .setTitle("CDP access token")
                .setView(tokenView)
                .setPositiveButton("Copy token", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        ClipboardManager clipboard = (ClipboardManager)
                                getSystemService(Context.CLIPBOARD_SERVICE);
                        clipboard.setPrimaryClip(ClipData.newPlainText("CDP access token", token));
                        Toast.makeText(MainActivity.this, "CDP token copied", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Close", null)
                .show();
    }

    /** In-app channel (page -> Java), independent of CDP. */
    public class Bridge {
        @JavascriptInterface
        public String ping() {
            return "pong from app pid " + android.os.Process.myPid()
                    + " at " + System.currentTimeMillis();
        }

        /** Introspection: which socket should an outside client aim at? */
        @JavascriptInterface
        public String info() {
            int pid = android.os.Process.myPid();
            return "{\"pid\":" + pid
                    + ",\"socket\":\"webview_devtools_remote_" + pid
                    + "\",\"relay\":\"127.0.0.1:" + RelayServer.PORT
                    + "\",\"uptime_ms\":" + android.os.SystemClock.elapsedRealtime() + "}";
        }

        /** Prove that a CDP call really crossed into the Android layer. */
        @JavascriptInterface
        public String toast(final String text) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, text, Toast.LENGTH_SHORT).show();
                }
            });
            return "toasted: " + text;
        }
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
