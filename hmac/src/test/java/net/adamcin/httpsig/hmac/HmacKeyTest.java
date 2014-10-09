package net.adamcin.httpsig.hmac;

import net.adamcin.httpsig.api.Algorithm;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class HmacKeyTest {

    static final String UTF_8 = "UTF-8";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldBeAbleToVerify() throws Exception {
        assertThat(new HmacKey("", "").canVerify(), is(true));
    }

    @Test
    public void shouldBeAbleToSign() throws Exception {
        assertThat(new HmacKey("", "").canSign(), is(true));
    }

    @Test
    public void shouldReturnSuppliedId() throws Exception {
        assertThat(new HmacKey("myId", "").getId(), is("myId"));
    }

    @Test
    public void shouldSupportHmacSha256() throws Exception {
        assertThat(new HmacKey("", "").getAlgorithms(), hasItem(Algorithm.HMAC_SHA256));
    }

    @Test
    public void shouldSupportHmacSha512() throws Exception {
        assertThat(new HmacKey("", "").getAlgorithms(), hasItem(Algorithm.HMAC_SHA512));
    }

    @Test
    public void shouldCreateVerifiableSignature() throws Exception {
        HmacKey key = new HmacKey("key1", "abcd");

        byte[] sig = key.sign(Algorithm.HMAC_SHA256, "hello".getBytes(UTF_8));

        assertThat(key.verify(Algorithm.HMAC_SHA256, "hello".getBytes(UTF_8), sig), is(true));
    }

    @Test
    public void shouldFailVerificationIfSigningAndVerifyingAlgorithmsAreDifferent() throws Exception {
        HmacKey key = new HmacKey("key1", "abcd");

        byte[] sig = key.sign(Algorithm.HMAC_SHA256, "hello".getBytes(UTF_8));

        assertThat(key.verify(Algorithm.HMAC_SHA512, "hello".getBytes(UTF_8), sig), is(false));
    }

    @Test
    public void shouldFailVerificationIfSignatureDoesNotMatch() throws Exception {
        HmacKey key = new HmacKey("key1", "abcd");

        byte[] sig = key.sign(Algorithm.HMAC_SHA256, "hello1".getBytes(UTF_8));

        assertThat(key.verify(Algorithm.HMAC_SHA512, "hello".getBytes(UTF_8), sig), is(false));
    }

    @Test
    public void signingShouldThrowIfUnsupportAlgorithm() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Unsupported algorithm: hmac-sha1");

        HmacKey key = new HmacKey("key1", "abcd");

        key.sign(Algorithm.HMAC_SHA1, "hello".getBytes(UTF_8));
    }

    @Test
    public void verifyingReturnFalseIfUnsupportedAlgorithm() throws Exception {
        HmacKey key = new HmacKey("key1", "abcd");

        byte[] sig = key.sign(Algorithm.HMAC_SHA256, "hello".getBytes(UTF_8));

        key.verify(Algorithm.HMAC_SHA1, "hello".getBytes(UTF_8), sig);
    }
}