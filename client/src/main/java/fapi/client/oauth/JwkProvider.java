package fapi.client.oauth;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.PS256;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import fapi.client.config.FapiConfig;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class JwkProvider {

    static final private Logger logger = LoggerFactory.getLogger(JwkProvider.class);

    static final private List<JWSAlgorithm> SUPPORTED_JWS_ALGORITHM = Arrays.asList(PS256, ES256);

    static final private List<JWEAlgorithm> SUPPORTED_JWE_ALGORITHMS = Arrays.asList(RSA_OAEP, RSA_OAEP_256);
    @Autowired
    private FapiConfig fapiConfig;

    private JWK jwk;
    private JWK encryptionJwk;
    private List<JWK> jwks = new ArrayList<>();

    @PostConstruct
    public void generateKeys() throws Exception {
        JWSAlgorithm jwsAlg = JWSAlgorithm.parse(fapiConfig.getJwsAlg());
        if (!SUPPORTED_JWS_ALGORITHM.contains(jwsAlg)) {
            throw new Exception(jwsAlg + " is not supported");
        }
        this.jwk = generateJWK(jwsAlg, KeyUse.SIGNATURE);
        this.jwks.add(this.jwk);

        if (fapiConfig.getJweAlg() != null) {
            Algorithm jweAlg = JWEAlgorithm.parse(fapiConfig.getJweAlg());
            if (!SUPPORTED_JWE_ALGORITHMS.contains(jweAlg)) {
                throw new Exception(jweAlg + " is not supported");
            }
            this.encryptionJwk = generateJWK(jweAlg, KeyUse.ENCRYPTION);
            this.jwks.add(this.encryptionJwk);
        }
        logger.info("ClientJWKSet " + new JWKSet(jwks).toJSONObject(false));

    }

    public JWK getJwk() {
        return this.jwk;
    }

    public JWK getEncryptionJwk() {
        return this.encryptionJwk;
    }

    public Map<String, Object> getJWKSetEndpoint() {
        return new JWKSet(this.jwks).toJSONObject();
    }

    private JWK generateJWK(Algorithm jwsAlg, KeyUse keyUse) throws Exception {

        if (JWSAlgorithm.Family.EC.contains(jwsAlg)) {
            // @formatter:off
            return new ECKeyGenerator(Curve.P_256)
                            .keyIDFromThumbprint(true)
                            .keyUse(keyUse)
                            .algorithm(jwsAlg)
                            .generate();

        } else {
            // @formatter:off
            return new RSAKeyGenerator(2048)
                            .keyIDFromThumbprint(true)
                            .keyUse(keyUse)
                            .algorithm(jwsAlg)
                            .generate();
            // @formatter:on
        }
    }

}
