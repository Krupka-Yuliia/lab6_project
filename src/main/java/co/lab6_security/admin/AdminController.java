package co.lab6_security.admin;

import co.lab6_security.login_attempt.LoginAttempt;
import co.lab6_security.login_attempt.LoginAttemptRepository;
import co.lab6_security.users.Role;
import co.lab6_security.users.User;
import co.lab6_security.users.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final LoginAttemptRepository loginAttemptRepository;
    private final UserService userService;

    @GetMapping("/dashboard")
    public String adminDashboard(Model model) {
        List<User> users = userService.findAllUsers();
        List<LoginAttempt> recentAttempts = loginAttemptRepository.findTop10ByOrderByAttemptTimeDesc();

        model.addAttribute("users", users);
        model.addAttribute("totalUsers", users.size());
        model.addAttribute("activeUsers", users.stream().filter(User::isEnabled).count());
        model.addAttribute("lockedUsers", users.stream()
                .filter(userService::isAccountLocked).count());
        model.addAttribute("recentAttempts", recentAttempts);

        long todayTotal = loginAttemptRepository.countTodayAttempts();
        long todaySuccessful = loginAttemptRepository.countTodaySuccessful();
        model.addAttribute("todayTotal", todayTotal);
        model.addAttribute("todaySuccessful", todaySuccessful);
        model.addAttribute("todayFailed", todayTotal - todaySuccessful);

        return "admin-dashboard";
    }

    @GetMapping("/login-attempts")
    public String viewLoginAttempts(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String filter,
            Model model) {

        List<LoginAttempt> attempts;

        if (username != null && !username.isEmpty()) {
            attempts = loginAttemptRepository.findByUsernameOrderByAttemptTimeDesc(username);
        } else if ("failed".equals(filter)) {
            attempts = loginAttemptRepository.findAll().stream()
                    .filter(a -> !a.isSuccessful())
                    .sorted((a, b) -> b.getAttemptTime().compareTo(a.getAttemptTime()))
                    .collect(Collectors.toList());
        } else if ("today".equals(filter)) {
            LocalDateTime startOfDay = LocalDateTime.now().withHour(0).withMinute(0).withSecond(0);
            attempts = loginAttemptRepository.findByAttemptTimeBetweenOrderByAttemptTimeDesc(
                    startOfDay, LocalDateTime.now());
        } else {
            attempts = loginAttemptRepository.findAll();
            attempts.sort((a, b) -> b.getAttemptTime().compareTo(a.getAttemptTime()));
        }

        long successfulAttempts = attempts.stream().filter(LoginAttempt::isSuccessful).count();
        long failedAttempts = attempts.size() - successfulAttempts;

        model.addAttribute("attempts", attempts);
        model.addAttribute("totalAttempts", attempts.size());
        model.addAttribute("successfulAttempts", successfulAttempts);
        model.addAttribute("failedAttempts", failedAttempts);
        model.addAttribute("selectedUsername", username);
        model.addAttribute("selectedFilter", filter);

        Map<String, Long> failedByUser = attempts.stream()
                .filter(a -> !a.isSuccessful())
                .collect(Collectors.groupingBy(LoginAttempt::getUsername, Collectors.counting()));
        model.addAttribute("topFailedUsers", failedByUser);

        return "admin-login-attempts";
    }

    @GetMapping("/users")
    public String viewUsers(Model model) {
        List<User> users = userService.findAllUsers();
        model.addAttribute("users", users);
        model.addAttribute("roles", Role.values());
        return "admin_users";
    }

    @PostMapping("/users/{userId}/unlock")
    public String unlockUser(@PathVariable Long userId) {
        userService.unlockUser(userId);
        return "redirect:/admin/users";
    }

    @PostMapping("/users/{userId}/change-role")
    public String changeUserRole(@PathVariable Long userId, @RequestParam Role role) {
        userService.changeUserRole(userId, role);
        return "redirect:/admin/users";
    }
}