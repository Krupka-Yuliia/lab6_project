package co.lab6_security.users;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Collections;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class TwoFactorAuthController {

    private final UserService userService;
    private final TwoFactorAuthService twoFactorAuthService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @GetMapping("/2fa")
    public String showTwoFactorAuthPage(@RequestParam String username, Model model, HttpSession session) {
        session.setAttribute("pendingUsername", username);
        model.addAttribute("username", username);
        return "two-factor-auth";
    }

    @PostMapping("/verify-2fa")
    public String verifyCode(
            @RequestParam String username,
            @RequestParam String code,
            Model model,
            HttpServletRequest request,
            HttpServletResponse response) {

        Optional<User> userOpt = userService.findByUsername(username);
        if (userOpt.isEmpty()) {
            model.addAttribute("error", "User not found");
            return "two-factor-auth";
        }

        User user = userOpt.get();
        if (twoFactorAuthService.validateCode(user, code)) {
            Authentication auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
            );

            ((UsernamePasswordAuthenticationToken) auth).setDetails(new WebAuthenticationDetails(request));

            SecurityContextHolder.getContext().setAuthentication(auth);
            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

            return "redirect:/home";
        } else {
            model.addAttribute("error", "Invalid or expired verification code");
            model.addAttribute("username", username);
            return "two-factor-auth";
        }
    }

    @GetMapping("/resend-2fa-code")
    public String resendCode(HttpSession session, Model model) {
        String username = (String) session.getAttribute("pendingUsername");
        if (username == null) {
            return "redirect:/login";
        }

        Optional<User> userOpt = userService.findByUsername(username);
        if (userOpt.isEmpty()) {
            return "redirect:/login";
        }

        User user = userOpt.get();
        boolean sent = twoFactorAuthService.generateAndSendCode(user);

        if (sent) {
            model.addAttribute("success", "A new verification code has been sent to your email");
        } else {
            model.addAttribute("error", "Failed to send verification code. Please try again.");
        }

        model.addAttribute("username", username);
        return "two-factor-auth";
    }
}