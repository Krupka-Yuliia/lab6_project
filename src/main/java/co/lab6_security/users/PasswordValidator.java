package co.lab6_security.users;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class PasswordValidator {

    public boolean isValid(String password) {
        return password != null &&
                password.length() >= 8 &&
                containsUppercaseLetter(password) &&
                containsLowercaseLetter(password) &&
                containsDigit(password) &&
                containsSpecialCharacter(password);
    }

    public List<String> getValidationErrors(String password) {
        List<String> errors = new ArrayList<>();

        if (password == null || password.length() < 8) {
            errors.add("Passes must be at least 8 characters long");
        }

        if (!containsUppercaseLetter(password)) {
            errors.add("Password must contain at least one uppercase letter");
        }

        if (!containsLowercaseLetter(password)) {
            errors.add("Password must contain at least one lowercase letter");
        }

        if (!containsDigit(password)) {
            errors.add("Password must contain at least one digit");
        }

        if (!containsSpecialCharacter(password)) {
            errors.add("Password must contain at least one special character");
        }

        return errors;
    }

    private boolean containsUppercaseLetter(String password) {
        return Pattern.compile("[A-Z]").matcher(password).find();
    }

    private boolean containsLowercaseLetter(String password) {
        return Pattern.compile("[a-z]").matcher(password).find();
    }

    private boolean containsDigit(String password) {
        return Pattern.compile("\\d").matcher(password).find();
    }

    private boolean containsSpecialCharacter(String password) {
        return Pattern.compile("[^a-zA-Z0-9]").matcher(password).find();
    }
}