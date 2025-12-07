package co.lab6_security.users;

import jakarta.mail.MessagingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordValidator passwordValidator;

    @Mock
    private UserMapper userMapper;

    @Mock
    private EmailService emailService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(userService, "baseUrl", "http://localhost:8080");
    }

    @Test
    void registerUser_WhenPasswordsDoNotMatch_ThrowsException() {
        UserDto userDto = new UserDto();
        userDto.setPassword("Password123!");
        userDto.setConfirmPassword("Different123!");

        assertThrows(IllegalArgumentException.class, () -> userService.registerUser(userDto));
    }

    @Test
    void registerUser_WhenPasswordValidationFails_ThrowsException() {
        UserDto userDto = new UserDto();
        userDto.setPassword("Password123!");
        userDto.setConfirmPassword("Password123!");
        userDto.setUsername("testuser");
        userDto.setEmail("test@example.com");

        when(passwordValidator.getValidationErrors(anyString())).thenReturn(List.of("Error"));

        assertThrows(IllegalArgumentException.class, () -> userService.registerUser(userDto));
    }

    @Test
    void registerUser_WhenUsernameExists_ThrowsException() {
        UserDto userDto = new UserDto();
        userDto.setPassword("Password123!");
        userDto.setConfirmPassword("Password123!");
        userDto.setUsername("existinguser");
        userDto.setEmail("test@example.com");

        when(passwordValidator.getValidationErrors(anyString())).thenReturn(List.of());
        when(userRepository.findByUsername("existinguser")).thenReturn(Optional.of(new User()));

        assertThrows(IllegalArgumentException.class, () -> userService.registerUser(userDto));
    }

    @Test
    void registerUser_WhenEmailExists_ThrowsException() {
        UserDto userDto = new UserDto();
        userDto.setPassword("Password123!");
        userDto.setConfirmPassword("Password123!");
        userDto.setUsername("newuser");
        userDto.setEmail("existing@example.com");

        when(passwordValidator.getValidationErrors(anyString())).thenReturn(List.of());
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("existing@example.com")).thenReturn(Optional.of(new User()));

        assertThrows(IllegalArgumentException.class, () -> userService.registerUser(userDto));
    }

    @Test
    void registerUser_WhenValid_CreatesUser() throws MessagingException {
        UserDto userDto = new UserDto();
        userDto.setPassword("Password123!");
        userDto.setConfirmPassword("Password123!");
        userDto.setUsername("newuser");
        userDto.setEmail("new@example.com");

        User user = new User();
        user.setEmail("new@example.com");

        when(passwordValidator.getValidationErrors(anyString())).thenReturn(List.of());
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(userMapper.toEntity(userDto)).thenReturn(user);
        when(userRepository.save(any(User.class))).thenReturn(user);

        assertDoesNotThrow(() -> userService.registerUser(userDto));
        verify(userRepository).save(any(User.class));
        verify(emailService).sendActivationEmail(anyString(), anyString());
    }

    @Test
    void activateUser_WhenTokenIsValid_ActivatesUser() {
        User user = new User();
        user.setEnabled(false);
        user.setActivationToken("valid-token");
        user.setTokenExpiry(LocalDateTime.now().plusHours(1));

        when(userRepository.findByActivationToken("valid-token")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        boolean result = userService.activateUser("valid-token");

        assertTrue(result);
        assertTrue(user.isEnabled());
        assertNull(user.getActivationToken());
        verify(userRepository).save(user);
    }

    @Test
    void activateUser_WhenTokenIsExpired_ReturnsFalse() {
        User user = new User();
        user.setActivationToken("expired-token");
        user.setTokenExpiry(LocalDateTime.now().minusHours(1));

        when(userRepository.findByActivationToken("expired-token")).thenReturn(Optional.of(user));

        boolean result = userService.activateUser("expired-token");

        assertFalse(result);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void activateUser_WhenTokenNotFound_ReturnsFalse() {
        when(userRepository.findByActivationToken("invalid-token")).thenReturn(Optional.empty());

        boolean result = userService.activateUser("invalid-token");

        assertFalse(result);
    }

    @Test
    void findByUsername_WhenUserExists_ReturnsUserDto() {
        User user = new User();
        user.setUsername("testuser");
        UserDto userDto = new UserDto();
        userDto.setUsername("testuser");

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(userMapper.toDto(user)).thenReturn(userDto);

        Optional<UserDto> result = userService.findByUsername("testuser");

        assertTrue(result.isPresent());
        assertEquals("testuser", result.get().getUsername());
    }

    @Test
    void findByUsername_WhenUserNotFound_ReturnsEmpty() {
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        Optional<UserDto> result = userService.findByUsername("nonexistent");

        assertTrue(result.isEmpty());
    }

    @Test
    void isAccountLocked_WhenUserIsLocked_ReturnsTrue() {
        User user = new User();
        user.setLockTime(LocalDateTime.now().minusMinutes(5));

        when(userRepository.findByUsername("lockeduser")).thenReturn(Optional.of(user));

        assertTrue(userService.isAccountLocked("lockeduser"));
    }

    @Test
    void isAccountLocked_WhenUserIsNotLocked_ReturnsFalse() {
        User user = new User();
        user.setLockTime(null);

        when(userRepository.findByUsername("unlockeduser")).thenReturn(Optional.of(user));

        assertFalse(userService.isAccountLocked("unlockeduser"));
    }

    @Test
    void isAccountLocked_WhenUserNotFound_ReturnsFalse() {
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        assertFalse(userService.isAccountLocked("nonexistent"));
    }

    @Test
    void unlockUser_WhenUserExists_UnlocksUser() {
        User user = new User();
        user.setId(1L);
        user.setLockTime(LocalDateTime.now());
        user.setFailedAttempts(5);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.unlockUser(1L);

        assertNull(user.getLockTime());
        assertEquals(0, user.getFailedAttempts());
        verify(userRepository).save(user);
    }

    @Test
    void unlockUser_WhenUserNotFound_ThrowsException() {
        when(userRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> userService.unlockUser(1L));
    }

    @Test
    void changeUserRole_WhenUserExists_ChangesRole() {
        User user = new User();
        user.setId(1L);
        user.setRole(Role.USER);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.changeUserRole(1L, Role.ADMIN);

        assertEquals(Role.ADMIN, user.getRole());
        verify(userRepository).save(user);
    }

    @Test
    void sendPasswordReset_WhenUserExists_SendsEmail() throws MessagingException {
        User user = new User();
        user.setEmail("test@example.com");

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        userService.sendPasswordReset("test@example.com");

        assertNotNull(user.getResetToken());
        assertNotNull(user.getResetTokenExpiry());
        verify(userRepository).save(user);
        verify(emailService).sendPasswordResetEmail(anyString(), anyString());
    }

    @Test
    void sendPasswordReset_WhenUserNotFound_ThrowsException() {
        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> userService.sendPasswordReset("nonexistent@example.com"));
    }

    @Test
    void resetPassword_WhenTokenIsValid_ResetsPassword() {
        User user = new User();
        user.setResetToken("valid-token");
        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(10));

        UserDto dto = new UserDto();
        dto.setNewPassword("NewPassword123!");
        dto.setConfirmNewPassword("NewPassword123!");

        when(userRepository.findByResetToken("valid-token")).thenReturn(Optional.of(user));
        when(passwordValidator.getValidationErrors(anyString())).thenReturn(List.of());
        when(passwordEncoder.encode(anyString())).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenReturn(user);

        boolean result = userService.resetPassword("valid-token", dto);

        assertTrue(result);
        assertNull(user.getResetToken());
        assertNull(user.getResetTokenExpiry());
        verify(userRepository).save(user);
    }

    @Test
    void resetPassword_WhenTokenIsExpired_ReturnsFalse() {
        User user = new User();
        user.setResetToken("expired-token");
        user.setResetTokenExpiry(LocalDateTime.now().minusMinutes(1));

        UserDto dto = new UserDto();
        dto.setNewPassword("NewPassword123!");
        dto.setConfirmNewPassword("NewPassword123!");

        when(userRepository.findByResetToken("expired-token")).thenReturn(Optional.of(user));

        boolean result = userService.resetPassword("expired-token", dto);

        assertFalse(result);
    }

    @Test
    void resetPassword_WhenPasswordsDoNotMatch_ThrowsException() {
        User user = new User();
        user.setResetToken("valid-token");
        user.setResetTokenExpiry(LocalDateTime.now().plusMinutes(10));

        UserDto dto = new UserDto();
        dto.setNewPassword("NewPassword123!");
        dto.setConfirmNewPassword("Different123!");

        when(userRepository.findByResetToken("valid-token")).thenReturn(Optional.of(user));
        when(passwordValidator.getValidationErrors(anyString())).thenReturn(List.of());

        assertThrows(IllegalArgumentException.class, () -> userService.resetPassword("valid-token", dto));
    }
}

