package co.lab6_security.two_factor;

import co.lab6_security.users.EmailService;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import jakarta.mail.MessagingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TwoFactorAuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private TwoFactorAuthService twoFactorAuthService;

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setEmail("test@example.com");
        user.setUsername("testuser");
    }

    @Test
    void generateAndSendCode_WhenUserIsNull_ReturnsFalse() {
        boolean result = twoFactorAuthService.generateAndSendCode(null);

        assertFalse(result);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void generateAndSendCode_WhenUserIsValid_GeneratesAndSendsCode() throws MessagingException {
        when(userRepository.save(any(User.class))).thenReturn(user);

        boolean result = twoFactorAuthService.generateAndSendCode(user);

        assertTrue(result);
        assertNotNull(user.getTwoFactorCode());
        assertNotNull(user.getTwoFactorCodeExpiry());
        assertEquals(6, user.getTwoFactorCode().length());
        verify(userRepository).save(user);
        verify(emailService).sendTwoFactorCode(anyString(), anyString());
    }

    @Test
    void generateAndSendCode_WhenEmailFails_ReturnsFalse() throws MessagingException {
        when(userRepository.save(any(User.class))).thenReturn(user);
        doThrow(new MessagingException("Email error")).when(emailService).sendTwoFactorCode(anyString(), anyString());

        boolean result = twoFactorAuthService.generateAndSendCode(user);

        assertFalse(result);
        verify(userRepository).save(user);
    }

    @Test
    void validateCode_WhenUserIsNull_ReturnsFalse() {
        boolean result = twoFactorAuthService.validateCode(null, "123456");

        assertFalse(result);
    }

    @Test
    void validateCode_WhenCodeIsNull_ReturnsFalse() {
        user.setTwoFactorCode("123456");
        user.setTwoFactorCodeExpiry(LocalDateTime.now().plusMinutes(10));

        boolean result = twoFactorAuthService.validateCode(user, null);

        assertFalse(result);
    }

    @Test
    void validateCode_WhenCodeIsExpired_ReturnsFalse() {
        user.setTwoFactorCode("123456");
        user.setTwoFactorCodeExpiry(LocalDateTime.now().minusMinutes(1));

        boolean result = twoFactorAuthService.validateCode(user, "123456");

        assertFalse(result);
    }

    @Test
    void validateCode_WhenCodeIsInvalid_ReturnsFalse() {
        user.setTwoFactorCode("123456");
        user.setTwoFactorCodeExpiry(LocalDateTime.now().plusMinutes(10));

        boolean result = twoFactorAuthService.validateCode(user, "000000");

        assertFalse(result);
    }

    @Test
    void validateCode_WhenCodeIsValid_ReturnsTrue() {
        user.setTwoFactorCode("123456");
        user.setTwoFactorCodeExpiry(LocalDateTime.now().plusMinutes(10));

        when(userRepository.save(any(User.class))).thenReturn(user);

        boolean result = twoFactorAuthService.validateCode(user, "123456");

        assertTrue(result);
        assertNull(user.getTwoFactorCode());
        assertNull(user.getTwoFactorCodeExpiry());
        verify(userRepository).save(user);
    }

    @Test
    void setTwoFactorEnabled_WhenUserExists_EnablesTwoFactor() {
        user.setTwoFactorEnabled(false);

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        twoFactorAuthService.setTwoFactorEnabled("testuser", true);

        assertTrue(user.isTwoFactorEnabled());
        verify(userRepository).save(user);
    }

    @Test
    void setTwoFactorEnabled_WhenUserNotFound_ThrowsException() {
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        assertThrows(java.util.NoSuchElementException.class, 
            () -> twoFactorAuthService.setTwoFactorEnabled("nonexistent", true));
    }
}

