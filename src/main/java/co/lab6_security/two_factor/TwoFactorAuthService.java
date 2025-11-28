package co.lab6_security.two_factor;

import co.lab6_security.users.EmailService;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TwoFactorAuthService {

    private final UserRepository userRepository;
    private final EmailService emailService;

    private static final int CODE_LENGTH = 6;
    private static final int CODE_EXPIRY_MINUTES = 10;

    private String generateRandomCode() {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(CODE_LENGTH);

        for (int i = 0; i < CODE_LENGTH; i++) {
            sb.append(random.nextInt(10));
        }

        return sb.toString();
    }

    public boolean generateAndSendCode(User user) {
        if (user == null) {
            return false;
        }

        String code = generateRandomCode();
        user.setTwoFactorCode(code);
        user.setTwoFactorCodeExpiry(LocalDateTime.now().plusMinutes(CODE_EXPIRY_MINUTES));
        userRepository.save(user);

        try {
            emailService.sendTwoFactorCode(user.getEmail(), code);
            return true;
        } catch (Exception e) {
            System.err.println("Failed to send 2FA code: " + e.getMessage());
            return false;
        }
    }

    public boolean validateCode(User user, String code) {
        if (user == null || code == null || user.getTwoFactorCode() == null || user.getTwoFactorCodeExpiry() == null) {
            return false;
        }

        if (LocalDateTime.now().isAfter(user.getTwoFactorCodeExpiry())) {
            return false;
        }

        boolean isValid = user.getTwoFactorCode().equals(code);

        if (isValid) {
            user.setTwoFactorCode(null);
            user.setTwoFactorCodeExpiry(null);
            userRepository.save(user);
        }

        return isValid;
    }

    public void setTwoFactorEnabled(String username, boolean enabled) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setTwoFactorEnabled(enabled);
        userRepository.save(user);
    }
}