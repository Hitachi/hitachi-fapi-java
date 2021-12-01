package fapi.client.oauth;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import fapi.client.ClientException;
import fapi.client.config.FapiConfig;
import fapi.client.util.CryptoUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Service
public class TokenExchange {
    static final private Logger logger = LoggerFactory.getLogger(TokenExchange.class);

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private OAuthSession session;

    @Autowired
    private FapiConfig fapiConfig;

    @Autowired
    private JwkProvider jwkProvider;

    @Autowired
    @Lazy
    private ServerMetadata metadata;

    public TokenResponse exchangeToken(String code) throws Exception {

        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.add("code", code);
        request.add("client_id", fapiConfig.getClientID());
        request.add("grant_type", "authorization_code");
        request.add("code_verifier", session.getCodeVerifer());
        request.add("redirect_uri", generateRedirectUri());

        if ("private_key_jwt".equals(fapiConfig.getClientAuthMethod())) {
            // @formatter:off
            String requestJwt = new RequestObjectBuilder()
                    .issuer(fapiConfig.getClientID())
                    .subject(fapiConfig.getClientID())
                    .audience(metadata.getTokenEndpoint())
                    .jti(CryptoUtil.generateRandomUUID())
                    .issuedAt(new Date())
                    .expirationAfter(Calendar.MINUTE, 5)
                    .buildAndSign(jwkProvider.getJwk());
            // @formatter:on
            request.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            request.add("client_assertion", requestJwt);
        }

        logger.info("TokenRequest " + request.toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity.post(metadata.getTokenEndpoint())
                .headers(headers).body(request);
        ResponseEntity<TokenResponse> result = restTemplate.exchange(requestEntity, TokenResponse.class);

        validateAccessTokenResponse(result.getBody());
        return result.getBody();
    }

    public TokenResponse refreshToken(String refreshToken) throws Exception {

        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.add("refresh_token", refreshToken);
        request.add("client_id", fapiConfig.getClientID());
        request.add("grant_type", "refresh_token");

        if ("private_key_jwt".equals(fapiConfig.getClientAuthMethod())) {
            // @formatter:off
            String requestJwt = new RequestObjectBuilder()
                    .issuer(fapiConfig.getClientID())
                    .subject(fapiConfig.getClientID())
                    .audience(metadata.getTokenEndpoint())
                    .jti(CryptoUtil.generateRandomUUID())
                    .issuedAt(new Date())
                    .expirationAfter(Calendar.MINUTE, 5)
                    .buildAndSign(jwkProvider.getJwk());
            // @formatter:on
            request.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            request.add("client_assertion", requestJwt);
        }

        logger.info("RefreshTokenRequest " + request.toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity.post(metadata.getTokenEndpoint())
                .headers(headers).body(request);
        ResponseEntity<TokenResponse> result = restTemplate.exchange(requestEntity, TokenResponse.class);

        validateRefreshTokenResponse(result.getBody());
        return result.getBody();
    }

    public void revokeToken(String refreshToken) throws Exception {
        StringBuilder revocationUrl = new StringBuilder();
        revocationUrl.append(metadata.getRevocationEndpoint());

        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.add("token", refreshToken);
        request.add("token_type_hint", "refresh_token");
        request.add("client_id", fapiConfig.getClientID());

        if ("private_key_jwt".equals(fapiConfig.getClientAuthMethod())) {
            // @formatter:off
            String requestJwt = new RequestObjectBuilder()
                    .issuer(fapiConfig.getClientID())
                    .subject(fapiConfig.getClientID())
                    .audience(fapiConfig.getIssuer())
                    .jti(CryptoUtil.generateRandomUUID())
                    .issuedAt(new Date())
                    .expirationAfter(Calendar.MINUTE, 5)
                    .buildAndSign(jwkProvider.getJwk());
            // @formatter:on
            request.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            request.add("client_assertion", requestJwt);
        }

        logger.info("RevokeTokenRequest " + request.toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity.post(revocationUrl.toString())
                .headers(headers).body(request);
        restTemplate.exchange(requestEntity, TokenResponse.class);

    }

    private void validateTokenResponse(TokenResponse response, Consumer<IDTokenValidator> c) throws Exception {
        logger.info(response.toString());
        IDTokenValidator validator = new IDTokenValidator(response.getIdToken());
        c.accept(validator);
        validator.verifiy(metadata.getJwkSet(), jwkProvider.getEncryptionJwk());

        if (response.getScope() != null && !validateScopes(response.getScope(), fapiConfig.getScopes())) {
            throw new ClientException("scope is not match at TokenResponse");
        }
        session.clearSession();
    }

    private void validateAccessTokenResponse(TokenResponse response) throws Exception {
        validateTokenResponse(response, validator -> {
            // @formatter:off
            validator
                .aud(fapiConfig.getClientID())
                .iss(fapiConfig.getIssuer())
                .nonce(session.getNonce())
                .notBefore(session.getNotBefore())
                .accessToken(response.getAccessToken());
            // @formatter:on
        });
    }

    private void validateRefreshTokenResponse(TokenResponse response) throws Exception {
        validateTokenResponse(response, validator -> {
            // @formatter:off
            validator
                .aud(fapiConfig.getClientID())
                .iss(fapiConfig.getIssuer())
                .notBefore(session.getNotBefore())
                .accessToken(response.getAccessToken());
            // @formatter:on
        });
    }

    private boolean validateScopes(String response, String[] scopes) {
        List<String> actualScopes = Arrays.asList(response.split(" "));
        List<String> expectedScopes = Arrays.asList(scopes);
        return actualScopes.size() == expectedScopes.size() && actualScopes.containsAll(expectedScopes);

    }

    private String generateRedirectUri() {
        String redirectUri = ServletUriComponentsBuilder.fromCurrentRequest().replacePath("/callback")
                .replaceQuery(null).toUriString();
        return redirectUri;
    }
}
