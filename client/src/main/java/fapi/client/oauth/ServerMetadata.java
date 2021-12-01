package fapi.client.oauth;

import java.net.URI;

import javax.annotation.PostConstruct;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.shaded.json.JSONObject;

import fapi.client.config.FapiConfig;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@Lazy
public class ServerMetadata {

    static final private Logger logger = LoggerFactory.getLogger(ServerMetadata.class);

    @Autowired
    private RestTemplate template;
    @Autowired
    private FapiConfig fapiConfig;

    private MetadataResponse metadata = null;
    private JWKSet jwkSet = null;

    @PostConstruct
    public void loadMetadata() throws Exception {
        URI issuer = URI.create(fapiConfig.getIssuer() + "/");
        URI wellKnown = issuer.resolve("./.well-known/openid-configuration");
        ResponseEntity<MetadataResponse> response = template.getForEntity(wellKnown, MetadataResponse.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            this.metadata = response.getBody();
            logger.info(this.metadata.toString());
            this.jwkSet = loadJwkSet(this.metadata.jwksUri);
            logger.info(this.jwkSet.toJSONObject().toString());
        }
    }

    private JWKSet loadJwkSet(String jwksUri) throws Exception {
        ResponseEntity<JSONObject> response = template.getForEntity(jwksUri, JSONObject.class);
        return JWKSet.parse(response.getBody());
    }

    public String getIssuer() {
        return this.metadata.issuer;
    }

    public String getAuthorizationEndpoint() {
        return this.metadata.authorizationEndpoint;
    }

    public JWKSet getJwkSet() {
        return this.jwkSet;
    }

    public String getTokenEndpoint() {
        return this.metadata.tokenEndpoint;
    }

    public String getRevocationEndpoint() {
        return this.metadata.revocationEndpoint;
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class MetadataResponse {
        private String issuer;
        private String authorizationEndpoint;
        private String tokenEndpoint;
        private String introspectionEndpoint;
        private String jwksUri;
        private String revocationEndpoint;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAuthorizationEndpoint() {
            return authorizationEndpoint;
        }

        public void setAuthorizationEndpoint(String authorizationEndpoint) {
            this.authorizationEndpoint = authorizationEndpoint;
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getIntrospectionEndpoint() {
            return introspectionEndpoint;
        }

        public void setIntrospectionEndpoint(String introspectionEndpoint) {
            this.introspectionEndpoint = introspectionEndpoint;
        }

        public String getJwksUri() {
            return jwksUri;
        }

        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }

        public String getRevocationEndpoint() {
            return revocationEndpoint;
        }

        public void setRevocationEndpoint(String revocationEndpoint) {
            this.revocationEndpoint = revocationEndpoint;
        }

        @Override
        public String toString() {
            return "MetadataResponse [authorizationEndpoint=" + authorizationEndpoint + ", introspectionEndpoint="
                    + introspectionEndpoint + ", issuer=" + issuer + ", jwksUri=" + jwksUri + ", tokenEndpoint="
                    + tokenEndpoint + "]";
        }

    }
}
