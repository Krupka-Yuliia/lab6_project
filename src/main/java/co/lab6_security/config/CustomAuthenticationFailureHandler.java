package co.lab6_security.config;

import co.lab6_security.login_attempt.LoginAttempt;
import co.lab6_security.login_attempt.LoginAttemptRepository;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserRepository userRepository;
    private final LoginAttemptRepository loginAttemptRepository;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 15;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String username = request.getParameter("username");

        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();

            if (isAccountLocked(user)) {
                long minutesUntilUnlock = getMinutesUntilUnlock(user);
                request.getSession().setAttribute("accountLocked", true);
                request.getSession().setAttribute("lockMinutes", minutesUntilUnlock);

                String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
                setDefaultFailureUrl("/login?error=true&username=" + encodedUsername);
                super.onAuthenticationFailure(request, response, exception);
                return;
            }

            LoginAttempt attempt = new LoginAttempt();
            attempt.setUsername(username);
            attempt.setSuccessful(false);
            loginAttemptRepository.save(attempt);

            int failedAttempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(failedAttempts);

            if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
                user.setLockTime(LocalDateTime.now());
            }

            userRepository.save(user);

            if (isAccountLocked(user)) {
                long minutesUntilUnlock = getMinutesUntilUnlock(user);
                request.getSession().setAttribute("accountLocked", true);
                request.getSession().setAttribute("lockMinutes", minutesUntilUnlock);
            }
        } else {
            LoginAttempt attempt = new LoginAttempt();
            attempt.setUsername(username);
            attempt.setSuccessful(false);
            loginAttemptRepository.save(attempt);
        }

        String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
        setDefaultFailureUrl("/login?error=true&username=" + encodedUsername);
        super.onAuthenticationFailure(request, response, exception);
    }

    private boolean isAccountLocked(User user) {
        if (user.getLockTime() == null) return false;
        LocalDateTime unlockTime = user.getLockTime().plusMinutes(LOCK_TIME_DURATION);
        return LocalDateTime.now().isBefore(unlockTime);
    }

    private long getMinutesUntilUnlock(User user) {
        if (user.getLockTime() == null) return 0;
        LocalDateTime unlockTime = user.getLockTime().plusMinutes(LOCK_TIME_DURATION);
        long minutes = java.time.Duration.between(LocalDateTime.now(), unlockTime).toMinutes();
        return Math.max(0, minutes);
    }
}