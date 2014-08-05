/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

package net.adamcin.httpsig.api;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Logger;

/**
 * Object used to pass per-request context, such as Request Line and HTTP Headers in client/server
 * implementation-independent way.
 */
public final class RequestContent implements Serializable {
    private static final Logger LOGGER = Logger.getLogger(RequestContent.class.getName());

    /**
     * The official format of the Date header value (and other date-type headers) is defined by
     * RFC 1123 ({@link #DATE_FORMAT_RFC1123})
     */
    @Deprecated
    public static final String DATE_FORMAT = "EEE MMM d HH:mm:ss yyyy zzz";

    public static final String DATE_FORMAT_RFC1123 = "EEE, dd MMM yyyy HH:mm:ss zzz";

    private static final List<String> SUPPORTED_DATE_FORMATS = Arrays.asList(DATE_FORMAT_RFC1123, DATE_FORMAT);

    private static final long serialVersionUID = -2968642080214687631L;

    @Deprecated
    private final String requestLine;
    private final String method;
    private final String path;
    private final Map<String, List<String>> headers;

    private RequestContent(final String requestLine, final String method, final String path, final Map<String, List<String>> headers) {
        this.requestLine = requestLine;
        this.method = method;
        this.path = path;
        this.headers = headers;
    }

    public static final class Builder {

        @Deprecated
        private String requestLine = null;

        private String method = null;
        private String path = null;
        private final Map<String, List<String>> headers = new LinkedHashMap<String, List<String>>();

        @Deprecated
        public Builder setRequestLine(String requestLine) {
            this.requestLine = requestLine;
            return this;
        }

        public Builder setRequestTarget(String method, String path) {
            this.method = method != null ? method.trim().toUpperCase() : null;
            this.path = path != null ? path.trim() : null;
            return this;
        }

        /**
         * Adds a header name and value pair
         *
         * @param name
         * @param value
         * @return
         */
        public Builder addHeader(final String name, final String value) {
            if (value != null) {
                final String _value = value.trim();
                final String _name = name.trim().toLowerCase();
                if (Constants.IGNORE_HEADERS.contains(_name) || _name.startsWith(":")) {
                /* skip ignored headers and names which begin with a colon */
                    return this;
                } else if (Constants.HEADER_REQUEST_LINE.equals(_name)) {
                    return this;
                } else if (Constants.HEADER_REQUEST_TARGET.equals(_name)) {
                    return this;
                } else if (!Constants.HEADER_DATE.equals(_name) || tryParseDate(_value) != null) {
                    List<String> values = null;
                    if (headers.containsKey(_name)) {
                        headers.get(_name);
                    } else {
                        values = new ArrayList<String>();
                        headers.put(_name, values);
                    }

                    if (values != null) {
                        values.add(_value);
                    }
                }
            }
            return this;
        }

        /**
         * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
         * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
         * merely a convenience method to generate a date header in the correct format.
         *
         * @param calendar the Calendar to provide
         * @return true if the date header was successfully set. false if date is already set
         */
        public Builder addDate(Calendar calendar) {
            if (calendar != null) {
                DateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT_RFC1123);
                dateFormat.setTimeZone(calendar.getTimeZone());
                this.addHeader(Constants.HEADER_DATE, dateFormat.format(calendar.getTime()));
            }
            return this;
        }

        /**
         * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
         * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
         * merely a convenience method to generate a date header in the correct format.
         *
         * @param dateGMT the current date in GMT
         * @return this {@link Builder}
         */
        public Builder addDate(Date dateGMT) {
            if (dateGMT != null) {
                Calendar calendar = new GregorianCalendar(getGMT());
                calendar.setTime(dateGMT);
                this.addDate(calendar);
            }
            return this;
        }

        /**
         * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
         * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
         * merely a convenience method to generate a date header in the correct format.
         *
         * @return this {@link Builder}
         */
        public Builder addDateNow() {
            addDate(new GregorianCalendar(getGMT()));
            return this;
        }

        public RequestContent build() {
            return new RequestContent(requestLine, method, path, Collections.unmodifiableMap(headers));
        }
    }

    /**
     * Returns the signature content as a byte array
     *
     * @param headers the list of headers to be included in the signed content
     * @return the result of {@link #getContentString(java.util.List)} encoded using the provided {@link Charset}
     */
    public byte[] getContent(List<String> headers, Charset charset) {
        return getContentString(headers).getBytes(charset);
    }

    /**
     * Returns the signature content as a String
     *
     * @param headers the list of headers to be included in the signed content
     * @return
     */
    public String getContentString(List<String> headers) {
        StringBuilder hashBuilder = new StringBuilder();
        if (headers != null) {
            for (String header : headers) {
                String _header = header.toLowerCase();
                if (!Constants.IGNORE_HEADERS.contains(_header) && !_header.startsWith(":")) {
                    if (Constants.HEADER_REQUEST_LINE.equals(_header)) {
                        if (this.requestLine != null) {
                            hashBuilder.append(this.requestLine).append('\n');
                        }
                    } else if (Constants.HEADER_REQUEST_TARGET.equals(_header)) {
                        if (this.getRequestTarget() != null) {
                            hashBuilder.append(this.getRequestTarget()).append('\n');
                        }
                    } else {
                        for (String value : this.getHeaderValues(_header)) {
                            hashBuilder.append(_header).append(": ").append(value).append('\n');
                        }
                    }
                }
            }
        }
        return hashBuilder.toString().trim();
    }

    @Override
    public String toString() {
        return getContentString(this.getHeaderNames());
    }

    /**
     * @return the list of header names contained in this {@link RequestContent}, in the order in which they were added, except
     *         for request-target, which is listed first if present
     */
    public List<String> getHeaderNames() {
        List<String> headerNames = new ArrayList<String>();
        if (method != null && path != null) {
            headerNames.add(Constants.HEADER_REQUEST_TARGET);
        }
        headerNames.addAll(this.headers.keySet());
        return Collections.unmodifiableList(headerNames);
    }

    /**
     * @return the request-line if set
     */
    @Deprecated
    public String getRequestLine() {
        return requestLine;
    }

    /**
     * @return the request-target if set
     */
    public String getRequestTarget() {
        if (method == null || path == null) {
            return null;
        } else {
            return method.toLowerCase() + " " + path;
        }
    }

    /**
     * @return the first date header value if set, null if not
     */
    public String getDate() {
        List<String> dateValues = getHeaderValues(Constants.HEADER_DATE);
        return dateValues.isEmpty() ? null : dateValues.get(0);
    }

    /**
     * @param name the name of the header
     * @return the list of values for the given header name, or an empty list if no values have been added.
     */
    public List<String> getHeaderValues(String name) {
        String _name = name.toLowerCase();
        if (Constants.HEADER_REQUEST_LINE.equals(_name)) {
            LOGGER.warning("[getHeaderValues] Use of the request-line header is deprecated. Please use (request-target) instead.");
            return this.requestLine != null ? Collections.singletonList(
                    this.requestLine
            ) : Collections.<String>emptyList();
        } else if (Constants.HEADER_REQUEST_TARGET.equals(_name)) {
            return this.getRequestTarget() != null ? Collections.singletonList(
                    this.getRequestTarget()
            ) : Collections.<String>emptyList();
        } else if (this.headers.containsKey(_name)) {
            return Collections.unmodifiableList(this.headers.get(_name));
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Sets the literal date header value.
     *
     * @param date a date string conforming to {@link #DATE_FORMAT_RFC1123} or to the deprecated {@link #DATE_FORMAT}
     * @return true if the date header was set successfully. false if the header is already set or the provided
     *         string does not conform to {@link #DATE_FORMAT_RFC1123} or to {@link #DATE_FORMAT}
     */
    protected static Date tryParseDate(String date) {
        if (date != null) {

            for (String formatString : SUPPORTED_DATE_FORMATS) {
                try {
                    DateFormat dateFormat = new SimpleDateFormat(formatString);
                    dateFormat.setTimeZone(getGMT());
                    return dateFormat.parse(date);
                } catch (ParseException e) {
                    LOGGER.warning("[tryParseDate] date string " + date + " does not match format " + formatString);
                }
            }
        }
        return null;
    }

    /**
     * Returns the currently set date header value converted to a {@link Date} object in the GMT time zone
     *
     * @return a {@link Date} object in GMT or null if header is not set or not valid
     */
    public Date getDateGMT() {
        if (this.getDate() != null) {
            return tryParseDate(this.getDate());
        }
        return null;
    }

    /**
     * Returns the currently set date header value converted to a {@link Calendar} in the specified timeZone, or in the
     * default timeZone if the parameter is null
     *
     * @param timeZone some time zone or null to convert to the default time zone
     * @return a {@link Calendar} in the specified time zone or in the default time zone if the timeZone parameter is null
     */
    public Calendar getDateTZ(TimeZone timeZone) {
        TimeZone tz = timeZone != null ? timeZone : TimeZone.getDefault();
        Date dateGMT = this.getDateGMT();
        if (dateGMT != null) {
            Calendar calGMT = new GregorianCalendar(getGMT());
            calGMT.setTime(dateGMT);
            return convertDate(calGMT, tz);
        }
        return null;
    }

    private static TimeZone getGMT() {
        return TimeZone.getTimeZone("UTC");
    }

    private static Calendar convertDate(Calendar orig, TimeZone to) {
        Calendar calendar = new GregorianCalendar(orig.getTimeZone());
        calendar.setTime(orig.getTime());
        calendar.add(Calendar.MILLISECOND, calendar.getTimeZone().getRawOffset() * -1);
        if (calendar.getTimeZone().inDaylightTime(calendar.getTime())) {
            calendar.add(Calendar.MILLISECOND, calendar.getTimeZone().getDSTSavings() * -1);
        }

        calendar.add(Calendar.MILLISECOND, to.getRawOffset());
        if (to.inDaylightTime(calendar.getTime())) {
            calendar.add(Calendar.MILLISECOND, to.getDSTSavings());
        }

        calendar.setTimeZone(to);

        return calendar;
    }

}
