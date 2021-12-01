package fapi.client.oauth;

import java.util.Calendar;
import java.util.Date;

import com.nimbusds.jose.jwk.JWK;

import fapi.client.ClientException;
import fapi.client.config.FapiConfig;
import fapi.client.util.CryptoUtil;
import fapi.client.util.OAuthUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class AuthorizationCodeGrant {

    static final private Logger logger = LoggerFactory.getLogger(AuthorizationCodeGrant.class);

    @Autowired
    @Lazy
    private ServerMetadata metadata;

    @Autowired
    private FapiConfig fapiConfig;

    @Autowired
    private JwkProvider jwksProvider;

    @Autowired
    private OAuthSession session;

    public String createAuthorizationUrl() throws Exception {
        String state = CryptoUtil.generateRandomUUID();
        String nonce = CryptoUtil.generateRandomUUID();
        String codeVerify = OAuthUtil.generateCodeVerifier();
        String codeChallenge = OAuthUtil.generateCodeChallenge(codeVerify);
        String redirectUri = generateRedirectUri();
        Date notBefore = new Date();

        session.setState(state);
        session.setNonce(nonce);
        session.setCodeVerifer(codeVerify);
        session.setRedirectUri(redirectUri);
        session.setNotBefore(notBefore);

        JWK jwk = jwksProvider.getJwk();
        // @formatter:off
        String requestObject = new RequestObjectBuilder()
                                    .responseType("code id_token")
                                    .responseMode("form_post")
                                    .clientID(fapiConfig.getClientID())
                                    .redirectURI(redirectUri)
                                    .codeChallenge(codeChallenge)
                                    .nonce(nonce)
                                    .state(state)
                                    .scopes(fapiConfig.getScopes())
                                    .issuer(fapiConfig.getClientID())
                                    .audience(fapiConfig.getIssuer())
                                    .notBefore(notBefore)
                                    .expirationAfter(Calendar.MINUTE, 5)
                                    .buildAndSign(jwk);
        // @formatter:on
        logger.info("RequestObject [" + requestObject + "]");
        return buildAuthorizationUrl(state, requestObject);
    }

    private String buildAuthorizationUrl(String state, String requestObject) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(metadata.getAuthorizationEndpoint());
        // @formatter:off
        return builder
            .queryParam("client_id", fapiConfig.getClientID())
            .queryParam("scope", String.join(" ", fapiConfig.getScopes()))
            .queryParam("response_type","code id_token")
            .queryParam("request", requestObject)
            .build()
            .toUriString();
        // @formatter:on
    }

    public boolean validateAuthorizationResponse(AuthorizationCodeResponse params) throws Exception {
        logger.info(params.toString());

        validateIdToken(params.getIdToken(), params.getCode(), params.getState());

        if (session.getState() == null || !session.getState().equals(params.getState())) {
            throw new ClientException(
                    String.format("state not match: actual[%s] expected[%s]", params.getState(), session.getState()));
        }
        if (session.getRedirectUri() == null || !session.getRedirectUri().equals(generateRedirectUri())) {
            throw new ClientException(String.format("redirect uri not match: actual[%s] expected[%s]",
                    generateRedirectUri(), session.getRedirectUri()));
        }

        return true;
    }

    private void validateIdToken(String idTokenString, String authzCode, String state) throws Exception {
        IDTokenValidator validator = new IDTokenValidator(idTokenString);
        // @formatter:off
            validator
                .iss(fapiConfig.getIssuer())
                .aud(fapiConfig.getClientID())
                .nonce(session.getNonce())
                .state(state)
                .code(authzCode)
                .notBefore(session.getNotBefore());
        // @formatter:on

        validator.verifiy(metadata.getJwkSet(), jwksProvider.getEncryptionJwk());
    }

    private String generateRedirectUri() {
        String redirectUri = ServletUriComponentsBuilder.fromCurrentRequest().replacePath("/callback")
                .replaceQuery(null).toUriString();
        return redirectUri;
    }

}
