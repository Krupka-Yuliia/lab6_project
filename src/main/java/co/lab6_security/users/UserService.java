package co.lab6_security.users;

import co.lab6_security.config.SecurityConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordValidator passwordValidator;
    private final UserMapper userMapper;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    public static final int MAX_FAILED_ATTEMPTS = SecurityConstants.MAX_FAILED_ATTEMPTS;

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

    public Optional<UserDto> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(userMapper::toDto);
    }

    public List<UserDto> findAllUsers() {
        return userRepository.findAll().stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());
    }

    public boolean isAccountLocked(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return false;
        }

        User user = userOpt.get();
        boolean isLocked = AccountLockUtils.isAccountLocked(user);

        if (!isLocked && user.getLockTime() != null) {
            user.setLockTime(null);
            user.setFailedAttempts(0);
            userRepository.save(user);
        }

        return isLocked;
    }

    public long getMinutesUntilUnlock(String username) {
        return userRepository.findByUsername(username)
                .map(AccountLockUtils::getMinutesUntilUnlock)
                .orElse(0L);
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

    public void sendPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User with this email does not exist"));

        String token = UUID.randomUUID().toString();
        user.setResetToken(token);
        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(15));

        userRepository.save(user);

        try {
            String resetLink = baseUrl + "/reset-password?token=" + token;
            emailService.sendPasswordResetEmail(email, resetLink);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send reset email: " + e.getMessage());
        }
    }

    public boolean resetPassword(String token, UserDto dto) {
        User user = userRepository.findByResetToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid reset token"));

        if (user.getResetTokenExpiry().isBefore(LocalDateTime.now())) {
            return false;
        }

        List<String> errors = passwordValidator.getValidationErrors(dto.getNewPassword());
        if (!errors.isEmpty()) {
            throw new RuntimeException(String.join(", ", errors));
        }

        if (!dto.getNewPassword().equals(dto.getConfirmNewPassword())) {
            throw new RuntimeException("Passwords do not match");
        }

        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);
        return true;
    }
}