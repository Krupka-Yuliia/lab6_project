package co.lab6_security.users;

import co.lab6_security.config.SecurityConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordValidator passwordValidator;
    private final UserMapper userMapper;
    private final EmailService emailService;

    public static final int MAX_FAILED_ATTEMPTS = SecurityConstants.MAX_FAILED_ATTEMPTS;
    public static final long LOCK_TIME_DURATION = SecurityConstants.LOCK_TIME_DURATION_MINUTES;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    public void registerUser(UserDto userDto) {
        if (!userDto.getPassword().equals(userDto.getConfirmPassword())) {
            throw new RuntimeException("Passwords do not match");
        }

        List<String> errors = passwordValidator.getValidationErrors(userDto.getPassword());
        if (!errors.isEmpty()) {
            throw new RuntimeException("Password validation failed: " + String.join(", ", errors));
        }

        if (userRepository.findByUsername(userDto.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = userMapper.toEntity(userDto);

        if (user.getRole() == null) {
            user.setRole(Role.USER);
        }

        String token = UUID.randomUUID().toString();
        user.setActivationToken(token);
        user.setTokenExpiry(LocalDateTime.now().plusHours(24));
        user.setEnabled(false);

        userRepository.save(user);

        try {
            String activationLink = baseUrl + "/activate?token=" + token;
            emailService.sendActivationEmail(user.getEmail(), activationLink);
        } catch (Exception e) {
            System.err.println("Failed to send activation email: " + e.getMessage());
        }
    }

    public boolean activateUser(String token) {
        Optional<User> userOpt = userRepository.findByActivationToken(token);
        if (userOpt.isPresent()) {
            User user = userOpt.get();

            if (user.getTokenExpiry() != null && user.getTokenExpiry().isBefore(LocalDateTime.now())) {
                return false;
            }

            user.setEnabled(true);
            user.setActivationToken(null);
            user.setTokenExpiry(null);
            userRepository.save(user);
            return true;
        }
        return false;
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public boolean isAccountLocked(User user) {
        boolean isLocked = AccountLockUtils.isAccountLocked(user);

        if (!isLocked && user.getLockTime() != null) {
            user.setLockTime(null);
            user.setFailedAttempts(0);
            userRepository.save(user);
        }

        return isLocked;
    }

    public long getMinutesUntilUnlock(User user) {
        return AccountLockUtils.getMinutesUntilUnlock(user);
    }

    public void unlockUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setLockTime(null);
        user.setFailedAttempts(0);
        userRepository.save(user);
    }

    public void changeUserRole(Long userId, Role newRole) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setRole(newRole);
        userRepository.save(user);
    }

    public User saveUser(User user) {
        return userRepository.save(user);
    }
}
