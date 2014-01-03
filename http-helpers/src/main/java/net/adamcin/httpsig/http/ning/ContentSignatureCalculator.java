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

package net.adamcin.httpsig.http.ning;

import com.ning.http.client.Body;
import com.ning.http.client.BodyGenerator;
import com.ning.http.client.ByteArrayPart;
import com.ning.http.client.FilePart;
import com.ning.http.client.FluentStringsMap;
import com.ning.http.client.Part;
import com.ning.http.client.Request;
import com.ning.http.client.RequestBuilderBase;
import com.ning.http.client.SignatureCalculator;
import com.ning.http.client.StringPart;
import com.ning.http.multipart.PartBase;
import com.ning.http.util.AsyncHttpProviderUtils;
import com.ning.http.util.UTF8UrlEncoder;
import net.adamcin.httpsig.api.Base64;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * {@link SignatureCalculator} implementation which generates a Content-MD5 header
 *
 * @since 1.0.4
 */
public class ContentSignatureCalculator implements SignatureCalculator {
    private static final Logger LOGGER = Logger.getLogger(ContentSignatureCalculator.class.getName());

    /**
     * {@inheritDoc}
     *
     * @param url
     * @param request
     * @param requestBuilder
     */
    public void calculateAndAddSignature(String url, Request request, RequestBuilderBase<?> requestBuilder) {
        calculateContentMD5(request, requestBuilder);
    }

    protected static void calculateContentMD5(Request request, RequestBuilderBase<?> requestBuilder) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            final String encoding = getBodyEncoding(request);
            if (request.getBodyGenerator() != null) {
                calculateFromBodyGenerator(request.getBodyGenerator(), requestBuilder, md);
            } else if (request.getEntityWriter() != null) {
                calculateFromEntityWriter(request.getEntityWriter(), requestBuilder, md);
            } else if (request.getFile() != null) {
                calculateFromFile(request.getFile(), requestBuilder, md);
            } else if (request.getByteData() != null) {
                calculateFromBytes(request.getByteData(), requestBuilder, md);
            } else if (request.getStringData() != null) {
                calculateFromString(request.getStringData(), encoding, requestBuilder, md);
            } else if (request.getParams() != null) {
                calculateFromParams(request.getParams(), encoding, requestBuilder, md);
            } else if (request.getParts() != null) {
                for (Part part : request.getParts()) {
                    if (part instanceof FilePart) {
                        calculateFromFile(((FilePart) part).getFile(), requestBuilder, md);
                    } else if (part instanceof ByteArrayPart) {
                        calculateFromBytes(((ByteArrayPart) part).getData(), requestBuilder, md);
                    } else if (part instanceof StringPart) {
                        String charset = ((StringPart) part).getCharset();
                        calculateFromString(
                                ((StringPart) part).getValue(), charset != null ? charset : encoding, requestBuilder, md
                        );
                    } else if (part instanceof PartBase) {
                        calculateFromPartBase((PartBase) part, requestBuilder, md);
                    }
                }
            }

            byte[] digest = md.digest();
            String headerValue = Base64.toBase64String(digest);

            if (headerValue != null && !headerValue.isEmpty()) {
                requestBuilder.addHeader("content-md5", headerValue);
            }
        } catch (Exception e) {
            LOGGER.severe("Error generating Content-MD5: " + e.getMessage());
        }
    }

    private static String getBodyEncoding(Request request) {
        return request.getBodyEncoding() != null ? request.getBodyEncoding()
                : AsyncHttpProviderUtils.DEFAULT_CHARSET;
    }


    private static void calculateFromEntityWriter(Request.EntityWriter entityWriter,
                                                  RequestBuilderBase<?> requestBuilder, MessageDigest md) throws Exception {

        File tempFile = null;
        OutputStream os = null;
        try {
            tempFile = File.createTempFile("crxPartBase", ".dat");
            os = new BufferedOutputStream(new FileOutputStream(tempFile));

            entityWriter.writeEntity(os);

            calculateFromFile(tempFile, requestBuilder, md);
        } finally {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }

            if (os != null) {
                try { os.close(); } catch (IOException e) { /* close quietly */ }
            }
        }
    }

    private static void calculateFromPartBase(PartBase part, RequestBuilderBase<?> requestBuilder, MessageDigest md) throws Exception {
        if (part.isRepeatable()) {
            File tempFile = null;
            OutputStream os = null;
            try {
                tempFile = File.createTempFile("crxPartBase", ".dat");
                os = new BufferedOutputStream(new FileOutputStream(tempFile));

                part.send(os);

                calculateFromFile(tempFile, requestBuilder, md);
            } finally {
                if (tempFile != null && tempFile.exists()) {
                    tempFile.delete();
                }

                if (os != null) {
                    try { os.close(); } catch (IOException e) { /* close quietly */ }
                }
            }
        }
    }

    private static void calculateFromBytes(byte[] data, RequestBuilderBase<?> requestBuilder, MessageDigest md) {
        md.update(data);
    }

    private static void calculateFromParams(FluentStringsMap params, String encoding,
                                            RequestBuilderBase<?> requestBuilder, MessageDigest md) throws Exception {

        StringBuilder sb = new StringBuilder();
        for (final Map.Entry<String, List<String>> paramEntry : params) {
            final String key = paramEntry.getKey();
            for (final String value : paramEntry.getValue()) {
                if (sb.length() > 0) {
                    sb.append("&");
                }
                UTF8UrlEncoder.appendEncoded(sb, key);
                sb.append("=");
                UTF8UrlEncoder.appendEncoded(sb, value);
            }
        }

        if (sb.length() > 0) {
            calculateFromString(sb.toString(), encoding, requestBuilder, md);
        }
    }

    private static void calculateFromString(String data, String encoding, RequestBuilderBase<?> requestBuilder,
                                            MessageDigest md) throws Exception {
        calculateFromBytes(data.getBytes(encoding), requestBuilder, md);
    }

    private static void calculateFromFile(File file, RequestBuilderBase<?> requestBuilder, MessageDigest md)
            throws Exception {
        FileChannel channel = null;
        try {
            Path path = FileSystems.getDefault().getPath(file.getAbsolutePath());
            channel = FileChannel.open(path, StandardOpenOption.READ);
            ByteBuffer buf = ByteBuffer.allocate(4096);

            while (channel.read(buf) >= 0) {
                md.update(buf);
            }
        } finally {
            if (channel != null) {
                try {
                    channel.close();
                } catch (Exception ignored) { /* close quietly */ }
            }
        }
    }

    private static void calculateFromBodyGenerator(BodyGenerator bodyGenerator,
                                                   RequestBuilderBase<?> requestBuilder, MessageDigest md)
            throws Exception {
        Body body = null;
        try {
            body = bodyGenerator.createBody();

            ByteBuffer buf = ByteBuffer.allocate(4096);

            while (body.read(buf) >= 0) {
                md.update(buf);
            }
        } finally {
            if (body != null) {
                try {
                    body.close();
                } catch (Exception ignored) { /* do nothing */ }
            }
        }
    }

}
