package co.lab6_security.config;

import co.lab6_security.users.CaptchaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import org.springframework.ui.Model;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.Map;

@AllArgsConstructor
@ControllerAdvice
public class GlobalExceptionHandler {

    private final CaptchaService captchaService;

    @ExceptionHandler(Exception.class)
    public String handleException(Exception e, Model model, HttpServletRequest request) {
        model.addAttribute("error", "Error occurred: " + e.getMessage());
        addCaptchaToModel(model, request.getSession());
        return "login";
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public String handleMissingParams(MissingServletRequestParameterException e, Model model, HttpServletRequest request) {
        model.addAttribute("error", "Necessary parameter is absent: " + e.getParameterName());
        addCaptchaToModel(model, request.getSession());
        return "login";
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public String handleTypeMismatch(MethodArgumentTypeMismatchException e, Model model, HttpServletRequest request) {
        model.addAttribute("error", "Incorrect parameter format: " + e.getName());
        addCaptchaToModel(model, request.getSession());
        return "login";
    }

    private void addCaptchaToModel(Model model, HttpSession session) {
        Map<String, String> captcha = captchaService.generateCaptcha(session.getId());
        model.addAttribute("captchaQuestion", captcha.get("question"));
    }
}
