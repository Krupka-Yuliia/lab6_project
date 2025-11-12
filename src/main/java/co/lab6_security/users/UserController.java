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

        User user = userService.findByUsername(username).orElse(null);
        boolean isAdmin = auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));

        model.addAttribute("username", username);
        model.addAttribute("email", user.getEmail() != null ? user.getEmail() : "");
        model.addAttribute("isAdmin", isAdmin);
        model.addAttribute("role", user.getRole().name());
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

        if (error != null) {
            model.addAttribute("error", "Invalid username or password");
        }
        if (logout != null) {
            model.addAttribute("success", "You have been logged out successfully");
        }

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
            userService.findByUsername(username).ifPresent(user -> {
                model.addAttribute("enteredUsername", username);

                if (userService.isAccountLocked(user)) {
                    model.addAttribute("lockedUser", user);
                    model.addAttribute("lockedUserLockMinutes", userService.getMinutesUntilUnlock(user));
                } else {
                    int remaining = UserService.MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
                    model.addAttribute("remainingAttempts", remaining);
                    model.addAttribute("failedAttempts", user.getFailedAttempts());
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

    @GetMapping("/access-denied")
    public String accessDenied(Model model) {
        model.addAttribute("error", "You don't have permission to access this page");
        return "access_denied";
    }
}