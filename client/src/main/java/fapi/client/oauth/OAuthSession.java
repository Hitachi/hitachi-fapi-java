package fapi.client.oauth;

import java.util.Date;

import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Service;
import org.springframework.web.context.WebApplicationContext;

@Service
@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class OAuthSession {

    private String state;
    private String nonce;
    private String codeVerifer;
    private String redirectUri;
    private Date notBefore;

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getCodeVerifer() {
        return codeVerifer;
    }

    public void setCodeVerifer(String codeVerifer) {
        this.codeVerifer = codeVerifer;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public void clearSession() {
        this.codeVerifer = null;
        this.nonce = null;
        this.state = null;
        this.redirectUri = null;
    }

}
