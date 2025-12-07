package co.lab6_security.two_factor;

import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
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

    private static final String REDIRECT_LOGIN = "redirect:/login";
    private static final String USERNAME_ATTRIBUTE = "username";
    private static final String TWO_FACTOR_AUTH_VIEW = "two-factor-auth";
    private static final String ERROR_ATTRIBUTE = "error";
    private static final String REDIRECT_HOME = "redirect:/home";
    private static final String SUCCESS_ATTRIBUTE = "success";

    private final UserRepository userRepository;
    private final TwoFactorAuthService twoFactorAuthService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @GetMapping("/2fa")
    public String showTwoFactorAuthPage(
            @RequestParam(required = false) String username,
            Model model,
            HttpSession session) {

        if (username == null) {
            username = (String) session.getAttribute("2FA_USER");
        }

        if (username == null) {
            return REDIRECT_LOGIN;
        }

        session.setAttribute("pendingUsername", username);
        model.addAttribute(USERNAME_ATTRIBUTE, username);
        return TWO_FACTOR_AUTH_VIEW;
    }

    @PostMapping("/verify-2fa")
    public String verifyCode(
            @RequestParam String username,
            @RequestParam String code,
            Model model,
            HttpServletRequest request,
            HttpServletResponse response) {

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            model.addAttribute(ERROR_ATTRIBUTE, "User not found");
            model.addAttribute(USERNAME_ATTRIBUTE, username);
            return TWO_FACTOR_AUTH_VIEW;
        }

        User user = userOpt.get();

        if (twoFactorAuthService.validateCode(user, code)) {
            var auth = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
            );

            auth.setDetails(new WebAuthenticationDetails(request));

            SecurityContextHolder.getContext().setAuthentication(auth);
            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

            return REDIRECT_HOME;
        } else {
            model.addAttribute(ERROR_ATTRIBUTE, "Invalid or expired verification code");
            model.addAttribute(USERNAME_ATTRIBUTE, username);
            return TWO_FACTOR_AUTH_VIEW;
        }
    }

    @GetMapping("/resend-2fa-code")
    public String resendCode(HttpSession session, Model model) {
        String username = (String) session.getAttribute("pendingUsername");
        if (username == null) {
            return REDIRECT_LOGIN;
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return REDIRECT_LOGIN;
        }

        User user = userOpt.get();
        boolean sent = twoFactorAuthService.generateAndSendCode(user);

        if (sent) {
            model.addAttribute(SUCCESS_ATTRIBUTE, "A new verification code has been sent to your email");
        } else {
            model.addAttribute(ERROR_ATTRIBUTE, "Failed to send verification code. Please try again.");
        }

        model.addAttribute(USERNAME_ATTRIBUTE, username);
        return TWO_FACTOR_AUTH_VIEW;
    }

    @PostMapping("/enable-2fa")
    public String enable2FA(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        twoFactorAuthService.setTwoFactorEnabled(username, true);

        model.addAttribute(SUCCESS_ATTRIBUTE, "Two-Factor Authentication has been enabled!");
        return REDIRECT_HOME;
    }

    @PostMapping("/disable-2fa")
    public String disable2FA(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();

        twoFactorAuthService.setTwoFactorEnabled(username, false);

        model.addAttribute(SUCCESS_ATTRIBUTE, "Two-Factor Authentication has been disabled!");
        return REDIRECT_HOME;
    }
}