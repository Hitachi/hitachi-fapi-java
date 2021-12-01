package fapi.client.oauth;

import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import fapi.client.ClientException;
import fapi.client.util.CryptoUtil;

public class IDTokenValidator {
    static final private List<JWEAlgorithm> NOT_ALLOWED_JWE_ALGOS = Arrays.asList(JWEAlgorithm.RSA1_5);
    static final private List<JWSAlgorithm> ALLOWED_JWS_ALGOS = Arrays.asList(JWSAlgorithm.PS256, JWSAlgorithm.ES256);
    private String idTokenString;
    private JWT jwt;
    private JWTClaimsSet.Builder expectedClaimsSet;
    private Date notBefore;

    public void verifiy(JWKSet jwkSet, JWK decryptionKey) throws Exception {

        if (this.jwt instanceof EncryptedJWT) {
            EncryptedJWT jwe = (EncryptedJWT) this.jwt;
            if (NOT_ALLOWED_JWE_ALGOS.contains(jwe.getHeader().getAlgorithm())) {
                throw new ClientException(
                        String.format("JWE Algorithm %s not allowed", jwe.getHeader().getAlgorithm().getName()));
            }

            JWEDecrypter decrypter = new RSADecrypter((RSAKey) decryptionKey);
            jwe.decrypt(decrypter);
            this.jwt = jwe.getPayload().toSignedJWT();

            // JWEDecryptionKeySelector<SecurityContext> decryptionKeySelector = new
            // JWEDecryptionKeySelector<>(jweAlg,
            // jweEnc, new ImmutableJWKSet<>(new JWKSet(decryptionKey)));
            // jwtProcessor.setJWEKeySelector(decryptionKeySelector);
        }

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                new HashSet<JWSAlgorithm>(ALLOWED_JWS_ALGOS), new ImmutableJWKSet<>(jwkSet));
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(this.expectedClaimsSet.build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp"))));

        JWTClaimsSet claims = jwtProcessor.process(jwt, null);
        if (claims.getIssueTime() != null && claims.getIssueTime().getTime() / 1000 < notBefore.getTime() / 1000) {
            throw new ClientException("invalid iat value");
        }
    }

    public IDTokenValidator(String idTokenString) throws Exception {
        this.idTokenString = idTokenString;
        this.jwt = JWTParser.parse(this.idTokenString);
        expectedClaimsSet = new JWTClaimsSet.Builder();
    }

    public IDTokenValidator iss(String iss) {
        this.expectedClaimsSet.issuer(iss);
        return this;
    }

    public IDTokenValidator aud(String aud) {
        this.expectedClaimsSet.audience(aud);
        return this;
    }

    public IDTokenValidator nonce(String nonce) {
        this.expectedClaimsSet.claim("nonce", nonce);
        return this;
    }

    public IDTokenValidator code(String code) {
        String cHash = CryptoUtil.calcurateXHash(code);
        this.expectedClaimsSet.claim("c_hash", cHash);
        return this;
    }

    public IDTokenValidator state(String state) {
        String sHash = CryptoUtil.calcurateXHash(state);
        this.expectedClaimsSet.claim("s_hash", sHash);
        return this;
    }

    public IDTokenValidator accessToken(String accessToken) {
        String atHash = CryptoUtil.calcurateXHash(accessToken);
        this.expectedClaimsSet.claim("at_hash", atHash);
        return this;
    }

    public IDTokenValidator notBefore(Date notBefore) {
        this.notBefore = notBefore;
        return this;
    }
}
