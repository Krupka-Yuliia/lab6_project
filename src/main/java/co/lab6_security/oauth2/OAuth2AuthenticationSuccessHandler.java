package co.lab6_security.oauth2;

import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        log.info("OAuth2 authentication successful for email: {}", email);

        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            log.error("User not found after OAuth2 authentication for email: {}", email);
            response.sendRedirect("/login?error=oauth2_error");
            return;
        }

        User user = userOpt.get();
        log.info("Found user: {}, enabled: {}, 2FA: {}", user.getUsername(), user.isEnabled(), user.isTwoFactorEnabled());

        UsernamePasswordAuthenticationToken newAuth = new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );

        SecurityContextHolder.getContext().setAuthentication(newAuth);
        log.info("Authentication set in SecurityContext for user: {}", user.getUsername());

        if (user.isTwoFactorEnabled()) {
            log.info("2FA enabled for user: {}, redirecting to 2FA verification", user.getUsername());
            request.getSession().setAttribute("2FA_USER", user.getUsername());
            String encodedUsername = URLEncoder.encode(user.getUsername(), StandardCharsets.UTF_8);
            response.sendRedirect("/2fa?username=" + encodedUsername);
            return;
        }

        log.info("Redirecting user {} to home page", user.getUsername());
        response.sendRedirect("/home");
    }
}