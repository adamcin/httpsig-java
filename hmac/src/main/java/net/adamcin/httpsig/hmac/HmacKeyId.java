package net.adamcin.httpsig.hmac;

import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.KeyId;

public class HmacKeyId implements KeyId {

    public String getId(Key key) {
        return key.getId();
    }
}
