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
public final class Request implements Serializable {
    private static final Logger LOGGER = Logger.getLogger(Request.class.getName());
    public static final String DATE_FORMAT = "EEE MMM d HH:mm:ss yyyy zzz";

    private String requestLine = null;
    private final Map<String, List<String>> headers = new LinkedHashMap<String, List<String>>();

    /**
     * Returns a byte array
     * @param headers the list of headers to be included in the signed content
     * @return
     */
    public byte[] getSignableContent(List<String> headers, Charset charset) {
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
        return hashBuilder.toString().trim().getBytes(charset);
    }

    /**
     * @return the list of header names contained in this {@link Request}, in the order in which they were added, except
     * for request-line and date
     */
    public List<String> getHeaderNames() {
        List<String> headerNames = new ArrayList<String>();
        if (requestLine != null) {
            headerNames.add(Constants.HEADER_REQUEST_LINE);
        }
        headerNames.addAll(this.headers.keySet());
        return Collections.unmodifiableList(headerNames);
    }

    public boolean setRequestLine(String requestLine) {
        if (this.requestLine == null) {
            this.requestLine = requestLine;
            return true;
        } else {
            return false;
        }
    }

    /**
     * Adds a header name and value pair
     * @param name
     * @param value
     * @return
     */
    public boolean addHeader(final String name, final String value) {
        final String _name = name.toLowerCase();
        if (_name.equals(Constants.AUTHORIZATION.toLowerCase()) || _name.startsWith(":")) {
            /* skip authorization headers and names which begin with a colon */
            return false;
        } else if (Constants.HEADER_REQUEST_LINE.equals(_name)) {
            return setRequestLine(value);
        } else if (!Constants.HEADER_DATE.equals(_name) || tryParseDate(value)) {
            List<String> values = null;
            if (headers.containsKey(_name)) {
                headers.get(_name);
            } else {
                values = new ArrayList<String>();
                headers.put(_name, values);
            }

            return values.add(value);
        }
        return false;
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
        if (this.headers.containsKey(_name)) {
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
    public boolean tryParseDate(String date) {
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
     * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
     * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
     * merely a convenience method to generate a date header in the correct format.
     * @param calendar the Calendar to provide
     * @return true if the date header was successfully set. false if date is already set
     */
    public boolean addDate(Calendar calendar) {
        if (calendar != null) {
            DateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
            dateFormat.setTimeZone(calendar.getTimeZone());
            return this.addHeader(Constants.HEADER_DATE, dateFormat.format(calendar.getTime()));
        }
        return false;
    }

    /**
     * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
     * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
     * merely a convenience method to generate a date header in the correct format.
     * @param dateGMT the current date in GMT
     * @return true if the date header was successfully set. false if date is already set
     */
    public boolean addDate(Date dateGMT) {
        if (dateGMT != null) {
            Calendar calendar = new GregorianCalendar(getGMT());
            calendar.setTime(dateGMT);
            return this.addDate(calendar);
        }
        return false;
    }

    /**
     * IMPORTANT: If you call this overload instead of {@link #addHeader(String, String)}, be sure to retrieve the
     * generated header value to add to your client request using a subsequent call to {@link #getDate()}. This is
     * merely a convenience method to generate a date header in the correct format.
     * @return true if the date header was successfully set. false if date is already set
     */
    public boolean addDateNow() {
        return addDate(new GregorianCalendar(getGMT()));
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
