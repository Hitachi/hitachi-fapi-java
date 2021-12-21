package fapi.server;

public class ResourceServerException extends RuntimeException {

    static String INVALID_REQUEST = "invalid_request";
    static String INVALID_TOKEN = "invalid_token";

    private String error;
    private String detail;
    private int status;

    public ResourceServerException(String error, String detail, int status) {
        this.error = error;
        this.detail = detail;
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public String getErrorString() {
        StringBuilder errorMsg = new StringBuilder();
        errorMsg.append("Bearer error=\"");
        errorMsg.append(this.error);
        errorMsg.append("\", error_description=\"");
        errorMsg.append(this.detail);
        errorMsg.append("\"");
        return errorMsg.toString();
    }
}
