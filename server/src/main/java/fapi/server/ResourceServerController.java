package fapi.server;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/")
public class ResourceServerController {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    @Lazy
    private ServerMetadata metadata;

    @RequestMapping("/")
    public Map<String, String> index() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "ok");
        return response;
    }

    @RequestMapping("/me")
    public Map<String, String> me(HttpServletRequest servletRequest) {
        Map<String, String> response = new HashMap<>();
        response.put("username", (String) servletRequest.getAttribute("username"));
        response.put("sub", (String) servletRequest.getAttribute("sub"));
        return response;
    }

    @RequestMapping("/echo/{value}")
    public Map<String, String> echo(@PathVariable(name = "value", required = false) String value) {
        Map<String, String> response = new HashMap<>();
        response.put("value", value);
        return response;
    }

    @RequestMapping("/introspection")
    public Object introspection(HttpServletRequest servletRequest) {
        String token = servletRequest.getHeader("Authorization") != null
                ? servletRequest.getHeader("Authorization").split(" ")[1]
                : "";
        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.add("token", token);
        request.add("client_id", "fapi-resource-server");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity
                .post(metadata.getIntrospectionEndpoint()).headers(headers).body(request);
        ResponseEntity<Object> result = restTemplate.exchange(requestEntity, Object.class);
        return result.getBody();
    }

    @RequestMapping("/headers")
    public Map<String, String> headers(HttpServletRequest servletRequest) throws Exception {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headernames = servletRequest.getHeaderNames();
        while (headernames.hasMoreElements()) {
            String name = headernames.nextElement();
            String header = servletRequest.getHeader(name);
            headers.put(name, header);
        }

        return headers;
    }
}
