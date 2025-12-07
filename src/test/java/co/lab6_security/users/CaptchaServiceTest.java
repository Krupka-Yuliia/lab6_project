package co.lab6_security.users;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;

class CaptchaServiceTest {

    private CaptchaService captchaService;

    @BeforeEach
    void setUp() {
        captchaService = new CaptchaService();
        ReflectionTestUtils.setField(captchaService, "secretKey", "test-secret-key");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"valid-response", "invalid-response", "response"})
    void validateRecaptcha_WhenResponseIsInvalid_ReturnsFalse(String response) {
        boolean result = captchaService.validateRecaptcha(response);
        assertFalse(result);
    }
}

