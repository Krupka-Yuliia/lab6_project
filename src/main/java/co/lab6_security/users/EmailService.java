package co.lab6_security.users;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;

    public void sendActivationEmail(String to, String activationLink) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject("Account Activation");

        String content =
                "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>" +
                        "<h2>Account Activation</h2>" +
                        "<p>Thank you for registering! To activate your account, please click the link below:</p>" +
                        "<p><a href='" + activationLink + "' style='display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;'>Activate Account</a></p>" +
                        "<p>Or copy and paste this link into your browser:</p>" +
                        "<p>" + activationLink + "</p>" +
                        "<p>If you didn’t register on our website, please ignore this email.</p>" +
                        "</div>";

        helper.setText(content, true);

        mailSender.send(message);
    }
}
