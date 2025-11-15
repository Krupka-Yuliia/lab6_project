package co.lab6_security.users;

import co.lab6_security.config.SecurityConstants;

import java.time.LocalDateTime;

public class AccountLockUtils {
    public static boolean isAccountLocked(User user) {
        if (user.getLockTime() == null) return false;

        LocalDateTime unlockTime = user.getLockTime()
                .plusMinutes(SecurityConstants.LOCK_TIME_DURATION_MINUTES);

        return LocalDateTime.now().isBefore(unlockTime);
    }

    public static long getMinutesUntilUnlock(User user) {
        if (user.getLockTime() == null) return 0;

        LocalDateTime unlockTime = user.getLockTime()
                .plusMinutes(SecurityConstants.LOCK_TIME_DURATION_MINUTES);

        long minutes = java.time.Duration.between(LocalDateTime.now(), unlockTime).toMinutes();
        return Math.max(0, minutes);
    }
}