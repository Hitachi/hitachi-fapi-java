package fapi.client;

import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Service;
import org.springframework.web.context.WebApplicationContext;

import fapi.client.oauth.TokenResponse;

@Service
@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class ClientSession {

    private TokenResponse tokenResponse;

    public TokenResponse getTokenResponse() {
        return tokenResponse;
    }

    public void setTokenResponse(TokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
    }

    public String getAccessTokenString() {
        return tokenResponse != null ? tokenResponse.getAccessToken() : null;
    }

    public String getRefreshTokenString() {
        return tokenResponse != null ? tokenResponse.getRefreshToken() : null;
    }

    public String getIDTokenString() {
        return tokenResponse != null ? tokenResponse.getIdToken() : null;
    }

}
