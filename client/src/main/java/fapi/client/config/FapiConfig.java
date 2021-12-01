package fapi.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "fapi.config")
public class FapiConfig {
    private String issuer;
    private String clientID;
    private String clientAuthMethod;

    private String[] resourceServers;

    private String jwsAlg;
    private String jweAlg;

    private String[] scopes;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getClientAuthMethod() {
        return clientAuthMethod;
    }

    public void setClientAuthMethod(String clientAuthMethod) {
        this.clientAuthMethod = clientAuthMethod;
    }

    public String[] getResourceServers() {
        return resourceServers;
    }

    public void setResourceServers(String[] resourceServers) {
        this.resourceServers = resourceServers;
    }

    public String getJwsAlg() {
        return jwsAlg;
    }

    public void setJwsAlg(String jwsAlg) {
        this.jwsAlg = jwsAlg;
    }

    public String getJweAlg() {
        return jweAlg;
    }

    public void setJweAlg(String jweAlg) {
        this.jweAlg = jweAlg;
    }

    public String[] getScopes() {
        return scopes;
    }

    public void setScopes(String[] scopes) {
        this.scopes = scopes;
    }

}
