package co.lab6_security.config;

import co.lab6_security.login_attempt.LoginAttempt;
import co.lab6_security.login_attempt.LoginAttemptRepository;
import co.lab6_security.users.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;

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

        userRepository.findByUsername(username).ifPresent(user -> {
            user.setFailedAttempts(0);
            user.setLockTime(null);
            userRepository.save(user);
        });

        setDefaultTargetUrl("/home");
        super.onAuthenticationSuccess(request, response, authentication);
    }
}