package fapi.client;

import java.net.URI;
import java.util.Map;

import fapi.client.oauth.AuthorizationCodeGrant;
import fapi.client.oauth.AuthorizationCodeResponse;
import fapi.client.oauth.JwkProvider;
import fapi.client.oauth.TokenExchange;
import fapi.client.oauth.TokenResponse;
import fapi.client.util.CryptoUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
@RequestMapping("/")
public class ClientController {

    @Autowired
    private AuthorizationCodeGrant authzCode;

    @Autowired
    private TokenExchange tokenExchange;

    @Autowired
    private JwkProvider jwksEndpoint;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ClientSession clientSession;

    @RequestMapping("/")
    public String index() {
        return "index";
    }

    @RequestMapping("/auth")
    public String authorization() throws Exception {
        return "redirect:" + authzCode.createAuthorizationUrl();
    }

    @RequestMapping(path = "/callback", method = RequestMethod.POST, consumes = {
            MediaType.APPLICATION_FORM_URLENCODED_VALUE })
    public String callback(@RequestBody MultiValueMap<String, String> params) throws Exception {
        boolean result = authzCode.validateAuthorizationResponse(new AuthorizationCodeResponse(params));
        if (result) {
            TokenResponse response = tokenExchange.exchangeToken(params.getFirst("code"));
            clientSession.setTokenResponse(response);
        }
        return "redirect:/";
    }

    @RequestMapping(path = "/callback", method = RequestMethod.GET)
    public String callbackForFragment() throws Exception {
        return "callback";
    }

    @RequestMapping(path = "/call-api", method = RequestMethod.POST)
    public String callApi(@RequestParam("server") String server, @RequestParam("path") String path, Model model)
            throws Exception {
        URI uri = UriComponentsBuilder.fromUriString(server).path(path).build().toUri();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(clientSession.getAccessTokenString());
        headers.add("x-fapi-interaction-id", CryptoUtil.generateRandomUUID());

        RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, uri);

        ResponseEntity<String> response = restTemplate.exchange(request, String.class);
        model.addAttribute("response", response.getBody());
        model.addAttribute("headers", response.getHeaders());
        return "index";
    }

    @RequestMapping(path = "/refresh")
    public String refreshToken(Model model) throws Exception {
        String refreshToken = clientSession.getRefreshTokenString();
        TokenResponse response = tokenExchange.refreshToken(refreshToken);
        clientSession.setTokenResponse(response);
        return "redirect:/";
    }

    @RequestMapping(value = "/revoke")
    public String logout(Model model) throws Exception {
        String refreshToken = clientSession.getRefreshTokenString();
        if (refreshToken == null) {
            return "forward:/";
        }

        tokenExchange.revokeToken(refreshToken);

        return "forward:/";
    }

    @RequestMapping("/jwk_set")
    @ResponseBody
    public Map<String, Object> jwkSet() {
        return jwksEndpoint.getJWKSetEndpoint();
    }

    @ExceptionHandler(value = { Exception.class })
    public String error(Exception exp, Model model) {
        model.addAttribute("err", exp.getMessage());
        exp.printStackTrace();
        return "index";
    }
}
