package co.lab6_security.users;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
    public String main() {
        return "redirect:/login";
    }

    @GetMapping("/home")
    public String successPage(Model model, HttpSession session) {
        String username = (String) session.getAttribute("username");
        if (username == null) {
            return "redirect:/login";
        }
        model.addAttribute("username", username);
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
    public String showLoginForm() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String username,
                            @RequestParam String password,
                            HttpSession session,
                            Model model) {
        try {
            userService.authenticateUser(username, password);
            session.setAttribute("username", username);
            return "redirect:/home";
        } catch (RuntimeException e) {
            if (e.getMessage().equals("User not found")) {
                model.addAttribute("error", "User not found. Please register.");
                model.addAttribute("redirectToRegister", true);
            } else {
                model.addAttribute("error", e.getMessage());
            }
            return "login";
        }
    }

    @GetMapping("/activate")
    public String activateAccount(@RequestParam String token, Model model) {
        boolean activated = userService.activateUser(token);

        if (activated) {
            model.addAttribute("success", "Your account have been activated successfully! You can log in now!");
        } else {
            model.addAttribute("error", "Expired or invalid activation token. Try again.");
        }

        return "activation";
    }


    @GetMapping("/logout")
    public String logout(HttpSession session, Model model) {
        session.invalidate();
        model.addAttribute("success", "You have been logged out");
        return "login";
    }
}