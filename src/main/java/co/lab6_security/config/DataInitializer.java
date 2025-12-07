package co.lab6_security.config;

import co.lab6_security.users.Role;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        String adminPassword = System.getenv("ADMIN_DEFAULT_PASSWORD");
        if (adminPassword == null || adminPassword.isEmpty()) {
            adminPassword = java.util.UUID.randomUUID().toString() + "!@#";
        }
        
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@example.com");
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setRole(Role.ADMIN);
            admin.setEnabled(true);
            admin.setFailedAttempts(0);
            admin.setIsOauth2User(false);


            userRepository.save(admin);
            log.info("Default admin user created with username: admin");
            log.warn("Please change the default admin password after first login!");
        }

        String userPassword = System.getenv("USER_DEFAULT_PASSWORD");
        if (userPassword == null || userPassword.isEmpty()) {
            userPassword = java.util.UUID.randomUUID().toString() + "!@#";
        }
        
        if (userRepository.findByUsername("user").isEmpty()) {
            User user = new User();
            user.setUsername("user");
            user.setEmail("user@example.com");
            user.setPassword(passwordEncoder.encode(userPassword));
            user.setRole(Role.USER);
            user.setEnabled(true);
            user.setFailedAttempts(0);
            user.setIsOauth2User(false);


            userRepository.save(user);
            log.info("Default user created with username: user");
            log.warn("Please change the default user password after first login!");
        }
    }
}
