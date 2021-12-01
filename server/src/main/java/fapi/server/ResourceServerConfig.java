package fapi.server;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "fapi.resource-server.config")
public class ResourceServerConfig {

    private String issuer;
    private String clientId;
    private String allowedScope;
    private String filteredPath;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String iss) {
        this.issuer = iss;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAllowedScope() {
        return allowedScope;
    }

    public void setAllowedScope(String allowedScope) {
        this.allowedScope = allowedScope;
    }

    public String getFilteredPath() {
        return filteredPath;
    }

    public void setFilteredPath(String filteredPath) {
        this.filteredPath = filteredPath;
    }

}
