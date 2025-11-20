package co.lab6_security.users;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class UserMapper {

    private final PasswordEncoder passwordEncoder;

    public User toEntity(UserDto dto) {
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setRole(dto.getRole());
        user.setTwoFactorEnabled(dto.isTwoFactorEnabled());
        return user;
    }

    public UserDto toDto(User user) {
        UserDto dto = new UserDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setRole(user.getRole());
        dto.setEnabled(user.isEnabled());
        dto.setFailedAttempts(user.getFailedAttempts() != null ? user.getFailedAttempts() : 0);
        dto.setAccountLocked(user.getLockTime() != null && AccountLockUtils.isAccountLocked(user));
        dto.setTwoFactorEnabled(user.isTwoFactorEnabled());

        if (dto.isAccountLocked()) {
            dto.setLockedMinutes(AccountLockUtils.getMinutesUntilUnlock(user));
        }

        dto.setRemainingAttempts(UserService.MAX_FAILED_ATTEMPTS - dto.getFailedAttempts());

        return dto;
    }
}