package co.lab6_security.users;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
public class UserController {

    private static final String SUCCESS_ATTRIBUTE = "success";
    private static final String RECAPTCHA_SITE_KEY_ATTRIBUTE = "recaptchaSiteKey";
    private static final String REGISTER_VIEW = "register";
    private static final String ERROR_ATTRIBUTE = "error";
    private static final String ACCOUNT_LOCKED_ATTRIBUTE = "accountLocked";
    private static final String RESET_PASSWORD_VIEW = "reset_password";

    private final UserService userService;
    private final CaptchaService captchaService;

    @Value("${recaptcha.site-key}")
    private String recaptchaSiteKey;

    @GetMapping("/")
    public String mainPage() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !auth.getPrincipal().equals("anonymousUser")) {
            return "redirect:/home";
        }
        return "redirect:/login";
    }

    @GetMapping("/home")
    public String successPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        UserDto userDto = userService.findByUsername(username).orElse(null);
        boolean isAdmin = auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));

        model.addAttribute("username", username);
        model.addAttribute("email", userDto != null ? userDto.getEmail() : "");
        model.addAttribute("isAdmin", isAdmin);
        model.addAttribute("role", userDto != null && userDto.getRole() != null ? userDto.getRole().name() : "");
        model.addAttribute("twoFactorEnabled", userDto != null && userDto.isTwoFactorEnabled());

        if (userDto != null) {
            User user = userService.findUserEntityByUsername(username).orElse(null);
            if (user != null && user.getOauth2Provider() != null) {
                model.addAttribute("oauth2Provider", user.getOauth2Provider());
            }
        }

        model.addAttribute(SUCCESS_ATTRIBUTE, "You are logged in!");

        return SUCCESS_ATTRIBUTE;
    }

    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("userDto", new UserDto());
        model.addAttribute(RECAPTCHA_SITE_KEY_ATTRIBUTE, recaptchaSiteKey);
        return REGISTER_VIEW;
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute UserDto userDto,
                               BindingResult result,
                               @RequestParam(name = "g-recaptcha-response") String recaptchaResponse,
                               Model model) {

        if (!captchaService.validateRecaptcha(recaptchaResponse)) {
            model.addAttribute(ERROR_ATTRIBUTE, "Please complete the reCAPTCHA verification.");
            model.addAttribute(RECAPTCHA_SITE_KEY_ATTRIBUTE, recaptchaSiteKey);
            return REGISTER_VIEW;
        }

        if (result.hasErrors()) {
            model.addAttribute(RECAPTCHA_SITE_KEY_ATTRIBUTE, recaptchaSiteKey);
            return REGISTER_VIEW;
        }

        try {
            userService.registerUser(userDto);
            model.addAttribute(SUCCESS_ATTRIBUTE, "Registration successful! Please check your email to activate your account.");
            return "activation";
        } catch (RuntimeException e) {
            model.addAttribute(ERROR_ATTRIBUTE, e.getMessage());
            model.addAttribute(RECAPTCHA_SITE_KEY_ATTRIBUTE, recaptchaSiteKey);
            return REGISTER_VIEW;
        }
    }

    @GetMapping("/login")
    public String showLoginForm(@RequestParam(required = false) String error,
                                @RequestParam(required = false) String logout,
                                @RequestParam(required = false) String username,
                                HttpSession session,
                                Model model) {

        if (error != null) model.addAttribute(ERROR_ATTRIBUTE, "Invalid username or password");
        if (logout != null) model.addAttribute(SUCCESS_ATTRIBUTE, "You have been logged out successfully");

        model.addAttribute("maxAttempts", UserService.MAX_FAILED_ATTEMPTS);

        Boolean accountLocked = (Boolean) session.getAttribute(ACCOUNT_LOCKED_ATTRIBUTE);
        Long lockMinutes = (Long) session.getAttribute("lockMinutes");

        if (Boolean.TRUE.equals(accountLocked) && lockMinutes != null) {
            model.addAttribute(ACCOUNT_LOCKED_ATTRIBUTE, true);
            model.addAttribute("lockedUserLockMinutes", lockMinutes);
            session.removeAttribute(ACCOUNT_LOCKED_ATTRIBUTE);
            session.removeAttribute("lockMinutes");
        }

        if (username != null && !username.isEmpty()) {
            userService.findByUsername(username).ifPresent(userDto -> {
                model.addAttribute("enteredUsername", username);

                if (userService.isAccountLocked(username)) {
                    model.addAttribute("lockedUser", userDto);
                    model.addAttribute("lockedUserLockMinutes", userService.getMinutesUntilUnlock(username));
                } else {
                    int remainingAttempts = UserService.MAX_FAILED_ATTEMPTS - userDto.getFailedAttempts();
                    model.addAttribute("remainingAttempts", remainingAttempts);
                    model.addAttribute("failedAttempts", userDto.getFailedAttempts());
                }
            });
        }

        return "login";
    }

    @GetMapping("/activate")
    public String activateAccount(@RequestParam String token, Model model) {
        boolean activated = userService.activateUser(token);

        if (activated) {
            model.addAttribute(SUCCESS_ATTRIBUTE, "Your account has been activated successfully! You can log in now!");
        } else {
            model.addAttribute(ERROR_ATTRIBUTE, "Expired or invalid activation token. Try again.");
        }

        return "activation";
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordPage() {
        return "forgot_password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam String email, Model model) {
        try {
            userService.sendPasswordReset(email);
            model.addAttribute(SUCCESS_ATTRIBUTE, "We sent you a reset link!");
        } catch (RuntimeException e) {
            model.addAttribute(ERROR_ATTRIBUTE, e.getMessage());
        }
        return "forgot_password";
    }

    @GetMapping("/reset-password")
    public String showResetForm(@RequestParam String token, Model model) {
        model.addAttribute("token", token);
        model.addAttribute("userDto", new UserDto());
        return RESET_PASSWORD_VIEW;
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam String token,
                                       @ModelAttribute UserDto dto,
                                       Model model) {

        try {
            boolean ok = userService.resetPassword(token, dto);
            if (ok) {
                model.addAttribute(SUCCESS_ATTRIBUTE, "Password changed successfully!");
                return "login";
            } else {
                model.addAttribute(ERROR_ATTRIBUTE, "Token expired. Please try again.");
                return RESET_PASSWORD_VIEW;
            }
        } catch (RuntimeException e) {
            model.addAttribute(ERROR_ATTRIBUTE, e.getMessage());
            model.addAttribute("token", token);
            return RESET_PASSWORD_VIEW;
        }
    }

    @GetMapping("/access-denied")
    public String accessDenied(Model model) {
        if (!model.containsAttribute(ERROR_ATTRIBUTE)) {
            model.addAttribute(ERROR_ATTRIBUTE, "You do not have permission to access this page");
        }
        return "access_denied";
    }
}