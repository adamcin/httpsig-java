package net.adamcin.httpsig.api;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Object used to pass per-request context, such as Request Line and HTTP Headers in client/server
 * implementation-independent way
 */
public final class Request implements Serializable {
    public static final DateFormat DATE_FORMAT = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy zzz");

    private Charset charset = Constants.CHARSET_LOGIN_ID;
    private final Map<String, String> headers = new HashMap<String, String>();

    public Request(Charset charset) {
        this.charset = charset;
    }

    public void setRequestLine(String requestLine) {
        headers.put(Constants.HEADER_REQUEST_LINE, requestLine);
    }

    public boolean setHeader(final String name, final String value) {
        final String _name = name.toLowerCase();
        if (!headers.containsKey(_name)) {
            headers.put(_name, value);
            return true;
        } else {
            return false;
        }
    }

    public String getHeader(String name) {
        return headers.get(name.toLowerCase());
    }

    public byte[] getHash(List<String> headers) {
        StringBuilder hashBuilder = new StringBuilder("");
        if (headers != null) {
            for (String header : headers) {
                String _header = header.toLowerCase();
                if (this.headers.containsKey(_header)) {
                    if (_header.equals(Constants.HEADER_REQUEST_LINE)) {
                        hashBuilder.append(this.headers.get(_header)).append("\n");
                    } else {
                        hashBuilder.append(_header).append(": ")
                                .append(this.headers.get(_header)).append("\n");
                    }
                }
            }
        }
        return hashBuilder.toString().trim().getBytes(charset);
    }
}
