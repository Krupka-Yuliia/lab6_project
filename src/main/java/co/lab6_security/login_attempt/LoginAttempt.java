package co.lab6_security.login_attempt;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "login_attempts")
@Data
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private boolean successful;
    @Column(name = "attempt_time", nullable = false)
    private LocalDateTime attemptTime;

    @PrePersist
    protected void onCreate() {
        attemptTime = LocalDateTime.now();
    }
}
