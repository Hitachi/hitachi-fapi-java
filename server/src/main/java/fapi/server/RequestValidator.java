package fapi.server;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import fapi.server.TokenIntrospectionResponse.CNF;

@Component
public class RequestValidator implements Filter {

    static final private Logger logger = LoggerFactory.getLogger(RequestValidator.class);

    @Autowired
    @Lazy
    private ServerMetadata metadata;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ResourceServerConfig config;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;
        String id = Optional.ofNullable(servletRequest.getHeader("x-fapi-interaction-id"))
                .orElse(UUID.randomUUID().toString());
        logger.info("x-fapi-interaction-id [" + id + "]");
        try {
            if (config.getFilteredPath() == null
                    || servletRequest.getRequestURI().startsWith(config.getFilteredPath())) {
                validateRequest(servletRequest);
            }
            servletResponse.setDateHeader("Date", System.currentTimeMillis());
            servletResponse.setHeader("x-fapi-interaction-id", id);
            chain.doFilter(request, response);
        } catch (ResourceServerException e) {
            servletResponse.setHeader("WWW-Authenticate", e.getErrorString());
            servletResponse.sendError(e.getStatus());
            logger.error("x-fapi-interaction-id={}, {}", id , e.getErrorString());
        }

    }

    private void validateRequest(HttpServletRequest servletRequest) throws ResourceServerException {
        if (servletRequest.getQueryString() != null) {
            throw new ResourceServerException(ResourceServerException.INVALID_REQUEST,
                    "included invalid query parameters",
                    HttpServletResponse.SC_BAD_REQUEST);
        }

        String authHeader = servletRequest.getHeader("Authorization");
        if (authHeader == null) {
            throw new ResourceServerException("", "", HttpServletResponse.SC_UNAUTHORIZED);
        }

        String token = authHeader.split(" ")[1];
        TokenIntrospectionResponse introspectionResponse = executeTokenIntrospection(token);
        if (!introspectionResponse.isActive()) {
            throw new ResourceServerException(ResourceServerException.INVALID_TOKEN, "access token not active",
                    HttpServletResponse.SC_UNAUTHORIZED);
        }

        Date exp = new Date(introspectionResponse.getExp() * 1000);
        if (!exp.after(new Date())) {
            throw new ResourceServerException(ResourceServerException.INVALID_TOKEN, "introspection response expired",
                    HttpServletResponse.SC_UNAUTHORIZED);
        }

        X509Certificate[] certs = (X509Certificate[]) servletRequest
                .getAttribute("javax.servlet.request.X509Certificate");
        validateCnfValue(certs, introspectionResponse.getCnf());

        servletRequest.setAttribute("username", introspectionResponse.getPreferredUsername());
        servletRequest.setAttribute("sub", introspectionResponse.getSub());
    }

    private TokenIntrospectionResponse executeTokenIntrospection(String token) {
        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.add("token", token);
        request.add("client_id", config.getClientId());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity
                .post(metadata.getIntrospectionEndpoint()).headers(headers).body(request);
        ResponseEntity<TokenIntrospectionResponse> result = restTemplate.exchange(requestEntity,
                TokenIntrospectionResponse.class);
        return result.getBody();
    }

    private void validateCnfValue(X509Certificate[] certs, CNF cnf) throws ResourceServerException {
        if (certs == null || certs.length == 0) {
            throw new ResourceServerException(ResourceServerException.INVALID_TOKEN,
                    "request has no certificates information", HttpServletResponse.SC_UNAUTHORIZED);
        }

        if (cnf == null || cnf.getX5t() == null) {
            throw new ResourceServerException(ResourceServerException.INVALID_TOKEN,
                    "IntrospectionResponse has no cnf value", HttpServletResponse.SC_UNAUTHORIZED);
        }
        String actual = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(certs[0].getEncoded());
            byte[] digest = md.digest();

            actual = Base64Url.encode(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (!cnf.getX5t().equals(actual)) {
            throw new ResourceServerException(ResourceServerException.INVALID_TOKEN,
                    String.format("x5t#S256 is not match: expected [%s], actual [%s]", cnf.getX5t(), actual),
                    HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

}
