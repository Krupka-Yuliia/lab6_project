package co.lab6_security.users;

import co.lab6_security.config.SecurityConstants;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class AccountLockUtilsTest {

    @Test
    void isAccountLocked_WhenLockTimeIsNull_ReturnsFalse() {
        User user = new User();
        user.setLockTime(null);

        assertFalse(AccountLockUtils.isAccountLocked(user));
    }

    @Test
    void isAccountLocked_WhenAccountIsLocked_ReturnsTrue() {
        User user = new User();
        user.setLockTime(LocalDateTime.now().minusMinutes(5));

        assertTrue(AccountLockUtils.isAccountLocked(user));
    }

    @Test
    void isAccountLocked_WhenAccountIsUnlocked_ReturnsFalse() {
        User user = new User();
        user.setLockTime(LocalDateTime.now().minusMinutes(SecurityConstants.LOCK_TIME_DURATION_MINUTES + 1));

        assertFalse(AccountLockUtils.isAccountLocked(user));
    }

    @Test
    void getMinutesUntilUnlock_WhenLockTimeIsNull_ReturnsZero() {
        User user = new User();
        user.setLockTime(null);

        assertEquals(0, AccountLockUtils.getMinutesUntilUnlock(user));
    }

    @Test
    void getMinutesUntilUnlock_WhenAccountIsLocked_ReturnsPositiveMinutes() {
        User user = new User();
        user.setLockTime(LocalDateTime.now().minusMinutes(5));

        long minutes = AccountLockUtils.getMinutesUntilUnlock(user);
        assertTrue(minutes > 0);
        assertTrue(minutes <= SecurityConstants.LOCK_TIME_DURATION_MINUTES);
    }

    @Test
    void getMinutesUntilUnlock_WhenAccountIsUnlocked_ReturnsZero() {
        User user = new User();
        user.setLockTime(LocalDateTime.now().minusMinutes(SecurityConstants.LOCK_TIME_DURATION_MINUTES + 1));

        assertEquals(0, AccountLockUtils.getMinutesUntilUnlock(user));
    }
}

