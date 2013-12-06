package net.adamcin.httpsig.clientauth.http3;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.Signer;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.auth.AuthenticationException;
import org.apache.commons.httpclient.auth.RFC2617Scheme;

public final class Http3SSHKeyAuthScheme extends RFC2617Scheme {

    public String getSchemeName() {
        return Constants.SCHEME;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    public String authenticate(Credentials credentials, String method, String uri) throws AuthenticationException {
        throw new AuthenticationException("SSHKey authentication requires access to Host and User-Agent headers");
    }

    public String authenticate(Credentials credentials, HttpMethod method) throws AuthenticationException {
        if (credentials instanceof SignerCredentials) {
            SignerCredentials creds = (SignerCredentials) credentials;
            String fingerprint = this.getParameter(Constants.FINGERPRINT);
            String sessionId = this.getParameter(Constants.NONCE);
            String algorithms = this.getParameter(Constants.ALGORITHMS);

            Header hostHeader = method.getRequestHeader(Constants.HOST);
            Header userAgentHeader = method.getRequestHeader(Constants.USER_AGENT);
            String host = hostHeader != null ? hostHeader.getValue() : "";
            String userAgent = userAgentHeader != null ? userAgentHeader.getValue() : "";

            Challenge challenge = new Challenge(this.getRealm(), fingerprint, sessionId, host, userAgent, Challenge.parseAlgorithms(algorithms));

            Signer signer = creds.getSigner();
            if (signer != null) {
                Authorization authorization = creds.getSigner().sign(challenge);
                if (authorization != null) {
                    return authorization.toString();
                }
            }
        }

        return null;
    }
}
