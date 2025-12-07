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

    private static final String UTF_8 = "UTF-8";

    private final JavaMailSender mailSender;

    public void sendActivationEmail(String to, String activationLink) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, UTF_8);

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

    public void sendTwoFactorCode(String to, String code) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, UTF_8);

        helper.setTo(to);
        helper.setSubject("Your Two-Factor Authentication Code");

        String content =
                "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>" +
                        "<h2>Two-Factor Authentication</h2>" +
                        "<p>Your verification code is:</p>" +
                        "<div style='font-size: 24px; font-weight: bold; padding: 15px; background-color: #f0f0f0; text-align: center; letter-spacing: 5px;'>" +
                        code +
                        "</div>" +
                        "<p>This code will expire in 10 minutes.</p>" +
                        "<p>If you didn't request this code, please ignore this email and consider changing your password.</p>" +
                        "</div>";

        helper.setText(content, true);

        mailSender.send(message);
    }

    public void sendPasswordResetEmail(String to, String resetLink) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, UTF_8);

        helper.setTo(to);
        helper.setSubject("Password Reset Request");

        String content = """
                <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                    <h2>Password Reset</h2>
                    <p>To reset your password, click the link below:</p>
                    <p><a href='%s'>Reset Password</a></p>
                    <p>This link is valid for 15 minutes.</p>
                </div>
                """.formatted(resetLink);

        helper.setText(content, true);
        mailSender.send(message);
    }

}
