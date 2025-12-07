package co.lab6_security.users;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

@Service
@Slf4j
public class CaptchaService {

    @Value("${recaptcha.secret-key}")
    private String secretKey;

    private static final String RECAPTCHA_VERIFY_URL =
            "https://www.google.com/recaptcha/api/siteverify";

    public boolean validateRecaptcha(String recaptchaResponse) {
        if (recaptchaResponse == null || recaptchaResponse.isEmpty()) {
            return false;
        }

        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> requestMap = new LinkedMultiValueMap<>();
        requestMap.add("secret", secretKey);
        requestMap.add("response", recaptchaResponse);

        try {
            Map<String, Object> response = restTemplate.postForObject(
                    RECAPTCHA_VERIFY_URL,
                    requestMap,
                    Map.class
            );

            if (response != null && response.containsKey("success")) {
                return (Boolean) response.get("success");
            }
        } catch (Exception e) {
            log.error("reCAPTCHA validation error: {}", e.getMessage(), e);
        }

        return false;
    }
}