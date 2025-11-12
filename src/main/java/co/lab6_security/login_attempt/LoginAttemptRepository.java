package co.lab6_security.login_attempt;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    List<LoginAttempt> findByUsernameOrderByAttemptTimeDesc(String username);


    List<LoginAttempt> findByAttemptTimeBetweenOrderByAttemptTimeDesc(
            LocalDateTime start, LocalDateTime end);

    List<LoginAttempt> findTop10ByOrderByAttemptTimeDesc();


    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE DATE(la.attemptTime) = CURRENT_DATE")
    long countTodayAttempts();

    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE DATE(la.attemptTime) = CURRENT_DATE " +
            "AND la.successful = true")
    long countTodaySuccessful();
}