package co.lab6_security.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ui.Model;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final String ERROR_ATTRIBUTE = "error";

    @Value("${recaptcha.site-key}")
    private String recaptchaSiteKey;

    @ExceptionHandler(Exception.class)
    public String handleException(Exception e, Model model, HttpServletRequest request) {
        model.addAttribute(ERROR_ATTRIBUTE, "Error occurred: " + e.getMessage());
        addRecaptchaToModel(model);
        return determineReturnPage(request);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public String handleMissingParams(MissingServletRequestParameterException e, Model model, HttpServletRequest request) {
        model.addAttribute(ERROR_ATTRIBUTE, "Necessary parameter is absent: " + e.getParameterName());
        addRecaptchaToModel(model);
        return determineReturnPage(request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public String handleTypeMismatch(MethodArgumentTypeMismatchException e, Model model, HttpServletRequest request) {
        model.addAttribute(ERROR_ATTRIBUTE, "Incorrect parameter format: " + e.getName());
        addRecaptchaToModel(model);
        return determineReturnPage(request);
    }

    private void addRecaptchaToModel(Model model) {
        model.addAttribute("recaptchaSiteKey", recaptchaSiteKey);
    }

    private String determineReturnPage(HttpServletRequest request) {
        String requestURI = request.getRequestURI();

        if (requestURI != null && requestURI.contains("/register")) {
            return "register";
        }

        return "login";
    }
}