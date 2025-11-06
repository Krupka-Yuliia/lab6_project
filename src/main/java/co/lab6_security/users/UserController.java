package co.lab6_security.users;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/")
    public String main() {
        return "redirect:/login";
    }

    @GetMapping("/home")
    public String successPage(Model model) {
        model.addAttribute("success", "You are logged in!");
        return "success";
    }


    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("userDto", new UserDto());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute UserDto userDto,
                               BindingResult result,
                               Model model) {
        if (result.hasErrors()) {
            return "register";
        }

        try {
            userService.registerUser(userDto);
            return "redirect:/login?registered";
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
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
                            Model model) {
        try {
            userService.authenticateUser(username, password);
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

    @GetMapping("/logout")
    public String logout(HttpSession session, Model model) {
        session.invalidate();
        model.addAttribute("success", "You have been logged out");
        return "login";
    }
}