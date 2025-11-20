package co.lab6_security.users;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final CaptchaService captchaService;

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
        model.addAttribute("twoFactorEnabled", userDto != null && userDto.isTwoFactorEnabled()); // ADD THIS LINE
        model.addAttribute("success", "You are logged in!");

        return "success";
    }

    @GetMapping("/register")
    public String showRegisterForm(Model model, HttpSession session) {
        model.addAttribute("userDto", new UserDto());
        Map<String, String> captcha = captchaService.generateCaptcha(session.getId());
        model.addAttribute("captchaQuestion", captcha.get("question"));
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute UserDto userDto,
                               BindingResult result,
                               @RequestParam("captchaAnswer") String captchaAnswer,
                               HttpSession session,
                               Model model) {

        if (!captchaService.validateCaptcha(session.getId(), captchaAnswer)) {
            model.addAttribute("error", "Incorrect captcha answer. Please try again.");
            Map<String, String> captcha = captchaService.generateCaptcha(session.getId());
            model.addAttribute("captchaQuestion", captcha.get("question"));
            return "register";
        }

        if (result.hasErrors()) {
            Map<String, String> captcha = captchaService.generateCaptcha(session.getId());
            model.addAttribute("captchaQuestion", captcha.get("question"));
            return "register";
        }

        try {
            userService.registerUser(userDto);
            model.addAttribute("success", "Registration successful! Please check your email to activate your account.");
            return "activation";
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
            Map<String, String> captcha = captchaService.generateCaptcha(session.getId());
            model.addAttribute("captchaQuestion", captcha.get("question"));
            return "register";
        }
    }

    @GetMapping("/login")
    public String showLoginForm(@RequestParam(required = false) String error,
                                @RequestParam(required = false) String logout,
                                @RequestParam(required = false) String username,
                                HttpSession session,
                                Model model) {

        if (error != null) model.addAttribute("error", "Invalid username or password");
        if (logout != null) model.addAttribute("success", "You have been logged out successfully");

        model.addAttribute("maxAttempts", UserService.MAX_FAILED_ATTEMPTS);

        Boolean accountLocked = (Boolean) session.getAttribute("accountLocked");
        Long lockMinutes = (Long) session.getAttribute("lockMinutes");

        if (Boolean.TRUE.equals(accountLocked) && lockMinutes != null) {
            model.addAttribute("accountLocked", true);
            model.addAttribute("lockedUserLockMinutes", lockMinutes);
            session.removeAttribute("accountLocked");
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
            model.addAttribute("success", "Your account has been activated successfully! You can log in now!");
        } else {
            model.addAttribute("error", "Expired or invalid activation token. Try again.");
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
            model.addAttribute("success", "We sent you a reset link!");
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
        }
        return "forgot_password";
    }

    @GetMapping("/reset-password")
    public String showResetForm(@RequestParam String token, Model model) {
        model.addAttribute("token", token);
        model.addAttribute("userDto", new UserDto());
        return "reset_password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam String token,
                                       @ModelAttribute UserDto dto,
                                       Model model) {

        try {
            boolean ok = userService.resetPassword(token, dto);
            if (ok) {
                model.addAttribute("success", "Password changed successfully!");
                return "login";
            } else {
                model.addAttribute("error", "Token expired. Please try again.");
                return "reset_password";
            }
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("token", token);
            return "reset_password";
        }
    }
}