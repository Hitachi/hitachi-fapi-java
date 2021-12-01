package fapi.client.oauth;

import org.springframework.util.MultiValueMap;

public class AuthorizationCodeResponse {

    private String code;
    private String error;
    private String errorDescription;
    private String idToken;
    private String state;

    public AuthorizationCodeResponse(MultiValueMap<String, String> params) {
        this.code = params.getFirst("code");
        this.idToken = params.getFirst("id_token");
        this.error = params.getFirst("error");
        this.errorDescription = params.getFirst("error_descrption");
        this.state = params.getFirst("state");
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    @Override
    public String toString() {
        return "AuthorizationCodeResponse [code=" + code + ", error=" + error + ", errorDescription=" + errorDescription
                + ", idToken=" + idToken + ", state=" + state + "]";
    }

}