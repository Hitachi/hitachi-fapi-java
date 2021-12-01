package fapi.client.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;

import fapi.client.oauth.IDTokenValidator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class IDTokenVelidatorTest {

    private static JWKSet jwkSet;

    private static final String code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
    private static final String cHash = "LDktKdoQak3Pk0cnXxCltA";
    private static final String state = "af0ifjsldkj";
    private static final String sHash = "bOhtX8F73IMjSPeVAqxyTQ";

    @BeforeAll
    public static void initJWKSet() throws Exception {
        JWK rsaJWK = new RSAKeyGenerator(2048).keyID("rsa").generate();
        JWK ecJWK = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
        JWK encKey = new RSAKeyGenerator(2048).keyID("enc").keyUse(KeyUse.ENCRYPTION).generate();
        jwkSet = new JWKSet(Arrays.asList(rsaJWK, ecJWK, encKey));
    }

    private SignedJWT createSignedJWT(JWSAlgorithm alg) throws Exception {
        // @formatter:off
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .audience("client")
                        .issuer("http://localhost:8080/auth/realms/fapi")
                        .subject("sub")
                        .issueTime(new Date())
                        .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                        .jwtID("1")
                        .claim("nonce", "12345")
                        .claim("c_hash", cHash)
                        .claim("s_hash", sHash)
                        .build();
        // @formatter:on
        return createSignedJWT(alg, claimsSet);
    }

    private SignedJWT createSignedJWT(JWSAlgorithm alg, JWTClaimsSet claimsSet) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(alg).type(JOSEObjectType.JWT);
        JWSSigner signer = null;
        if (alg == JWSAlgorithm.PS256) {
            header.keyID("rsa");
            signer = new RSASSASigner((RSAKey) jwkSet.getKeyByKeyId("rsa"));
        } else if (alg == JWSAlgorithm.ES256) {
            header.keyID("ec");
            signer = new ECDSASigner((ECKey) jwkSet.getKeyByKeyId("ec"));
        }

        SignedJWT jwt = new SignedJWT(header.build(), claimsSet);
        jwt.sign(signer);
        return jwt;
    }

    @Test
    public void validateSuccessWithPS256Jwt() throws Exception {
        JWT jwt = createSignedJWT(JWSAlgorithm.PS256);
        IDTokenValidator validator = new IDTokenValidator(jwt.serialize());
        // @formatter:off
        validator
            .iss("http://localhost:8080/auth/realms/fapi")
            .aud("client")
            .nonce("12345")
            .code(code)
            .state(state)
            .notBefore(new Date(new Date().getTime() - 10 * 1000))
            .verifiy(jwkSet, jwkSet.getKeyByKeyId("enc"));
        // @formatter:on
    }

    @Test
    public void validateSuccessWithES256Jwt() throws Exception {
        JWT jwt = createSignedJWT(JWSAlgorithm.ES256);
        IDTokenValidator validator = new IDTokenValidator(jwt.serialize());
        // @formatter:off
        validator
            .iss("http://localhost:8080/auth/realms/fapi")
            .aud("client")
            .nonce("12345")
            .code(code)
            .state(state)
            .notBefore(new Date())
            .verifiy(jwkSet, jwkSet.getKeyByKeyId("enc"));
        // @formatter:on
    }

    @Test
    public void validateFailedWithExpiredJWT() throws Exception {
        // @formatter:off
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .audience("client")
                        .issuer("http://localhost:8080/auth/realms/fapi")
                        .subject("sub")
                        .issueTime(new Date(new Date().getTime() - 90 * 1000))
                        .expirationTime(new Date(new Date().getTime() - 60 * 1000)) // <- invalid expirationTime
                        .jwtID("1")
                        .claim("nonce", "12345")
                        .claim("c_hash", cHash)
                        .claim("s_hash", sHash)
                        .build();
        // @formatter:on
        JWT jwt = createSignedJWT(JWSAlgorithm.PS256, claimsSet);
        IDTokenValidator validator = new IDTokenValidator(jwt.serialize());
        assertEquals(assertThrows(BadJWTException.class, () -> {
            // @formatter:off
            validator
                .iss("http://localhost:8080/auth/realms/fapi")
                .aud("client")
                .nonce("12345")
                .code(code)
                .state(state)
                .verifiy(jwkSet, jwkSet.getKeyByKeyId("enc"));
            // @formatter:on
        }).getMessage(), "Expired JWT");

    }
}
