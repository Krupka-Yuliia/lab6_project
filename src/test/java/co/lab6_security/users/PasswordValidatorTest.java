package co.lab6_security.users;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class PasswordValidatorTest {

    private PasswordValidator passwordValidator;

    @BeforeEach
    void setUp() {
        passwordValidator = new PasswordValidator();
    }

    @ParameterizedTest
    @MethodSource("invalidPasswordProvider")
    void getValidationErrors_WhenPasswordIsInvalid_ReturnsErrors(String password, String expectedError) {
        List<String> errors = passwordValidator.getValidationErrors(password);
        assertFalse(errors.isEmpty());
        assertTrue(errors.contains(expectedError));
    }

    static Stream<Arguments> invalidPasswordProvider() {
        return Stream.of(
            Arguments.of(null, "Password must be at least 8 characters long"),
            Arguments.of("Short1!", "Password must be at least 8 characters long"),
            Arguments.of("password123!", "Password must contain at least one uppercase letter"),
            Arguments.of("PASSWORD123!", "Password must contain at least one lowercase letter"),
            Arguments.of("Password!", "Password must contain at least one digit"),
            Arguments.of("Password123", "Password must contain at least one special character")
        );
    }

    @Test
    void getValidationErrors_WhenPasswordIsValid_ReturnsEmptyList() {
        List<String> errors = passwordValidator.getValidationErrors("ValidPass123!");
        assertTrue(errors.isEmpty());
    }

    @Test
    void getValidationErrors_WhenPasswordHasMultipleIssues_ReturnsMultipleErrors() {
        List<String> errors = passwordValidator.getValidationErrors("short");
        assertTrue(errors.size() > 1);
    }
}

