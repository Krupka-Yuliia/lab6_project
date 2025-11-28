package co.lab6_security.config;

import co.lab6_security.login_attempt.LoginAttempt;
import co.lab6_security.login_attempt.LoginAttemptRepository;
import co.lab6_security.two_factor.TwoFactorAuthService;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;
    private final TwoFactorAuthService twoFactorAuthService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String username = authentication.getName();

        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername(username);
        attempt.setSuccessful(true);
        loginAttemptRepository.save(attempt);

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setFailedAttempts(0);
            user.setLockTime(null);
            userRepository.save(user);

            if (user.isTwoFactorEnabled()) {
                twoFactorAuthService.generateAndSendCode(user);
                SecurityContextHolder.clearContext();
                response.sendRedirect("/2fa?username=" + username);
                return;
            }
        }

        setDefaultTargetUrl("/home");
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
