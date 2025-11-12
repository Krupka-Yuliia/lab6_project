package co.lab6_security.config;

import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.time.LocalDateTime;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationFailureHandler authenticationFailureHandler;
    private final CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    private final UserRepository userRepository;

    private static final long LOCK_TIME_DURATION = 15;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/activate", "/login", "/css/**", "/js/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler(authenticationFailureHandler)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .permitAll()
                )
                .exceptionHandling(exception -> exception
                        .accessDeniedPage("/access-denied")
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            if (!user.isEnabled()) {
                throw new BadCredentialsException("Account not activated");
            }

            if (user.getLockTime() != null) {
                LocalDateTime unlockTime = user.getLockTime().plusMinutes(LOCK_TIME_DURATION);

                if (LocalDateTime.now().isBefore(unlockTime)) {
                    long minutesLeft = java.time.Duration.between(LocalDateTime.now(), unlockTime).toMinutes();
                    throw new BadCredentialsException(
                            "Account is locked due to multiple failed login attempts. " +
                                    "Try again in " + (minutesLeft + 1) + " minute(s)."
                    );
                } else {
                    user.setLockTime(null);
                    user.setFailedAttempts(0);
                    userRepository.save(user);
                }
            }

            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getUsername())
                    .password(user.getPassword())
                    .roles(user.getRole().name())
                    .disabled(!user.isEnabled())
                    .build();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}