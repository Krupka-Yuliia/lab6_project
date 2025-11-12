package co.lab6_security.config;

import co.lab6_security.users.Role;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@example.com");
            admin.setPassword(passwordEncoder.encode("Admin123!"));
            admin.setRole(Role.ADMIN);
            admin.setEnabled(true);
            admin.setFailedAttempts(0);

            userRepository.save(admin);
            System.out.println("Default admin user created:");
            System.out.println("Username: admin");
            System.out.println("Password: Admin123!");
            System.out.println("Please change this password after first login!");
        }

        if (userRepository.findByUsername("user").isEmpty()) {
            User user = new User();
            user.setUsername("user");
            user.setEmail("user@example.com");
            user.setPassword(passwordEncoder.encode("User123!"));
            user.setRole(Role.USER);
            user.setEnabled(true);
            user.setFailedAttempts(0);

            userRepository.save(user);
            System.out.println("Default user created:");
            System.out.println("Username: user");
            System.out.println("Password: User123!");
        }
    }
}