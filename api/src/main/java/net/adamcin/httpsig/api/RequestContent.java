package net.adamcin.httpsig.api;

import java.io.Serializable;
import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.logging.Logger;

/**
 * Object used to pass per-request context, such as Request Line and HTTP Headers in client/server
 * implementation-independent way.
 */
public final class RequestContent implements Serializable {
    private static final Logger LOGGER = Logger.getLogger(RequestContent.class.getName());
    public static final String DATE_FORMAT = "EEE MMM d HH:mm:ss yyyy zzz";

    private static final long serialVersionUID = -2968642080214687631L;

    private final String requestLine;
    private final Map<String, List<String>> headers;

    private RequestContent(final String requestLine, final Map<String, List<String>> headers) {
        this.requestLine = requestLine;
        this.headers = headers;
    }

    public static final class Builder {

        private String requestLine = null;
        private final Map<String, List<String>> headers = new LinkedHashMap<String, List<String>>();

        public Builder setRequestLine(String requestLine) {
            this.requestLine = requestLine;
            return this;
        }

        /**
         * Adds a header name and value pair
         * @param name
         * @param value
         * @return
         */
        public Builder addHeader(final String name, final String value) {
            final String _name = name.toLowerCase();
            if (_name.equals(Constants.AUTHORIZATION.toLowerCase()) || _name.startsWith(":")) {
            /* skip authorization headers and names which begin with a colon */
                return this;
            } else if (Constants.HEADER_REQUEST_LINE.equals(_name)) {
                return this;
            } else if (!Constants.HEADER_DATE.equals(_name) || tryParseDate(value)) {
                List<String> values = null;
                if (headers.containsKey(_name)) {
                    headers.get(_name);
                } else {
                    values = new ArrayList<String>();
                    headers.put(_name, values);
                }

                if (values != null) {
                    values.add(value);
                }
            }
            return this;
        }

        /**
         * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
         * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
         * merely a convenience method to generate a date header in the correct format.
         * @param calendar the Calendar to provide
         * @return true if the date header was successfully set. false if date is already set
         */
        public Builder addDate(Calendar calendar) {
            if (calendar != null) {
                DateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
                dateFormat.setTimeZone(calendar.getTimeZone());
                this.addHeader(Constants.HEADER_DATE, dateFormat.format(calendar.getTime()));
            }
            return this;
        }

        /**
         * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
         * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
         * merely a convenience method to generate a date header in the correct format.
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
         * @return this {@link Builder}
         */
        public Builder addDateNow() {
            addDate(new GregorianCalendar(getGMT()));
            return this;
        }

        public RequestContent build() {
            return new RequestContent(requestLine, Collections.unmodifiableMap(headers));
        }
    }

    /**
     * Returns the signature content as a byte array
     * @param headers the list of headers to be included in the signed content
     * @return the result of {@link #getContentString(java.util.List)} encoded using the provided {@link Charset}
     */
    public byte[] getContent(List<String> headers, Charset charset) {
        return getContentString(headers).getBytes(charset);
    }

    /**
     * Returns the signature content as a String
     * @param headers the list of headers to be included in the signed content
     * @return
     */
    public String getContentString(List<String> headers) {
        StringBuilder hashBuilder = new StringBuilder("");
        if (headers != null) {
            for (String header : headers) {
                String _header = header.toLowerCase();
                if (Constants.HEADER_REQUEST_LINE.equals(_header)) {
                    if (this.requestLine != null) {
                        hashBuilder.append(this.requestLine).append("\n");
                    }
                } else {
                    for (String value : this.getHeaderValues(_header)) {
                        hashBuilder.append(_header).append(": ").append(value).append("\n");
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
     * for request-line, which is listed first if present
     */
    public List<String> getHeaderNames() {
        List<String> headerNames = new ArrayList<String>();
        if (requestLine != null) {
            headerNames.add(Constants.HEADER_REQUEST_LINE);
        }
        headerNames.addAll(this.headers.keySet());
        return Collections.unmodifiableList(headerNames);
    }


    /**
     * @return the request-line if set
     */
    public String getRequestLine() {
        return requestLine;
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
            return this.requestLine != null ? Collections.singletonList(this.requestLine) : Collections.<String>emptyList();
        } else if (this.headers.containsKey(_name)) {
            return Collections.unmodifiableList(this.headers.get(_name));
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Sets the literal date header value.
     * @param date a date string conforming to {@link #DATE_FORMAT}
     * @return true if the date header was set successfully. false if the header is already set or the provided
     *         string does not conform to {@link #DATE_FORMAT}
     */
    private static boolean tryParseDate(String date) {
        if (date != null) {
            try {
                DateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
                dateFormat.parse(date);
                return true;
            } catch (ParseException e) {
                LOGGER.warning("[addDate] date string " + date + " does not match format " + DATE_FORMAT);
            }
        }
        return false;
    }


    /**
     * Returns the currently set date header value converted to a {@link Date} object in the GMT time zone
     * @return a {@link Date} object in GMT or null if header is not set or not valid
     */
    public Date getDateGMT() {
        if (this.getDate() != null) {
            try {
                DateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
                dateFormat.setTimeZone(getGMT());
                return dateFormat.parse(this.getDate());
            } catch (ParseException e) {
                LOGGER.warning("[getDateGMT] date string " + this.getDate() + " does not match format " + DATE_FORMAT);
            }
        }
        return null;
    }

    /**
     * Returns the currently set date header value converted to a {@link Calendar} in the specified timeZone, or in the
     * default timeZone if the parameter is null
     * @param timeZone some time zone or null to convert to the default time zone
     * @return a {@link Calendar} in the specified time zone or in the default time zone if the timeZone parameter is null
     */
    public Calendar getDateTZ(TimeZone timeZone) {
        Date dateGMT = this.getDateGMT();
        TimeZone tz = timeZone != null ? timeZone : TimeZone.getDefault();
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
