package fapi.client.oauth;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class RequestObjectBuilder {

    private JWTClaimsSet.Builder claims;

    public RequestObjectBuilder() {
        this.claims = new JWTClaimsSet.Builder();
    }

    public String buildAndSign(JWK jwk) throws Exception {
        JWSAlgorithm alg = (JWSAlgorithm) jwk.getAlgorithm();

        JWSSigner signer;
        if (jwk.getKeyType() == KeyType.RSA) {
            signer = new RSASSASigner((RSAKey) jwk);
        } else {
            signer = new ECDSASigner((ECKey) jwk);
        }

        JWTClaimsSet payload = this.claims.build();
        SignedJWT jws = new SignedJWT(new JWSHeader.Builder(alg).type(JOSEObjectType.JWT).keyID(jwk.getKeyID()).build(),
                payload);
        jws.sign(signer);
        return jws.serialize();

    }

    public RequestObjectBuilder responseType(String responseType) {
        this.claims.claim("response_type", responseType);
        return this;
    }

    public RequestObjectBuilder responseMode(String responseMode) {
        this.claims.claim("response_mode", responseMode);
        return this;
    }

    public RequestObjectBuilder clientID(String clientID) {
        this.claims.claim("client_id", clientID);
        return this;
    }

    public RequestObjectBuilder redirectURI(String redirectURI) {
        this.claims.claim("redirect_uri", redirectURI);
        return this;
    }

    public RequestObjectBuilder state(String state) {
        this.claims.claim("state", state);
        return this;
    }

    public RequestObjectBuilder nonce(String nonce) {
        this.claims.claim("nonce", nonce);
        return this;
    }

    public RequestObjectBuilder codeChallenge(String codeChallenge) {
        this.claims.claim("code_challenge", codeChallenge);
        this.claims.claim("code_challenge_method", "S256");
        return this;
    }

    public RequestObjectBuilder scopes(String... scope) {
        this.claims.claim("scope", String.join(" ", scope));
        return this;
    }

    public RequestObjectBuilder issuer(String issuer) {
        this.claims.issuer(issuer);
        return this;
    }

    public RequestObjectBuilder audience(String audience) {
        this.claims.audience(audience);
        return this;
    }

    public RequestObjectBuilder audience(List<String> audience) {
        this.claims.audience(audience);
        return this;
    }

    public RequestObjectBuilder subject(String subject) {
        this.claims.subject(subject);
        return this;
    }

    public RequestObjectBuilder jti(String jti) {
        this.claims.jwtID(jti);
        return this;
    }

    public RequestObjectBuilder issuedAt(Date iat) {
        this.claims.issueTime(iat);
        return this;
    }

    public RequestObjectBuilder notBefore(Date nbf) {
        this.claims.notBeforeTime(nbf);
        return this;
    }

    public RequestObjectBuilder expirationAfter(int timeUnit, int min) {
        Calendar exp = Calendar.getInstance();
        exp.add(timeUnit, min);
        this.claims.expirationTime(exp.getTime());
        return this;
    }

}
