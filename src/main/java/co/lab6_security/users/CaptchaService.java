package co.lab6_security.users;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CaptchaService {
    private final Map<String, String> captchaStore = new ConcurrentHashMap<>();
    private final Random random = new Random();

    public Map<String, String> generateCaptcha(String sessionId) {
        int num1 = random.nextInt(10) + 1;
        int num2 = random.nextInt(10) + 1;
        String answer = String.valueOf(num1 + num2);

        captchaStore.put(sessionId, answer);

        Map<String, String> result = new HashMap<>();
        result.put("question", num1 + " + " + num2 + " = ?");
        return result;
    }

    public boolean validateCaptcha(String sessionId, String userAnswer) {
        String correctAnswer = captchaStore.get(sessionId);

        captchaStore.remove(sessionId);

        return correctAnswer != null && correctAnswer.equals(userAnswer);
    }
}
