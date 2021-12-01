package fapi.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class TokenIntrospectionResponse {
    private long exp;
    private long iat;
    private long authTime;
    private String jti;
    private String iss;
    private String sub;
    private String scope;
    private boolean active;
    private String preferredUsername;

    private CNF cnf;

    public class CNF {

        @JsonProperty("x5t#S256")
        private String x5t;

        public String getX5t() {
            return x5t;
        }

        public void setX5t(String x5t) {
            this.x5t = x5t;
        }

        @Override
        public String toString() {
            return "CNF [x5t#S256=" + x5t + "]";
        }

    }

    public long getExp() {
        return exp;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }

    public long getIat() {
        return iat;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }

    public long getAuthTime() {
        return authTime;
    }

    public void setAuthTime(long authTime) {
        this.authTime = authTime;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public CNF getCnf() {
        return cnf;
    }

    public void setCnf(CNF cnf) {
        this.cnf = cnf;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    @Override
    public String toString() {
        return "TokenIntrospectionResponse [active=" + active + ", authTime=" + authTime + ", cnf=" + cnf + ", exp="
                + exp + ", iat=" + iat + ", iss=" + iss + ", jti=" + jti + ", preferredUsername=" + preferredUsername
                + ", scope=" + scope + ", sub=" + sub + "]";
    }

}
