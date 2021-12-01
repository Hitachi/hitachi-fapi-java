package fapi.client.oauth;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import fapi.client.oauth.JwkProvider;

@SpringBootTest
public class KeystoreTest {
    @Autowired
    JwkProvider jwk;

    @Test
    public void test() throws Exception {
        assertNotNull(jwk.getJwk());
    }
}
