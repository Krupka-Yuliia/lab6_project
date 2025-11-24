package co.lab6_security.oauth2;

import co.lab6_security.users.Role;
import co.lab6_security.users.User;
import co.lab6_security.users.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        String providerId = oauth2User.getAttribute("sub");
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String givenName = oauth2User.getAttribute("given_name");
        String familyName = oauth2User.getAttribute("family_name");

        Boolean emailVerified = oauth2User.getAttribute("email_verified");
        if (emailVerified == null || !emailVerified) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_not_verified"),
                    "Email address is not verified"
            );
        }

        processOAuth2User(provider, providerId, email, name, givenName, familyName);
        return oauth2User;
    }

    private void processOAuth2User(String provider, String providerId, String email,
                                   String fullName, String givenName, String familyName) {

        Optional<User> existingUserByEmail = userRepository.findByEmail(email);

        if (existingUserByEmail.isPresent()) {
            User user = existingUserByEmail.get();

            if (Boolean.TRUE.equals(user.getIsOauth2User())) {
                if (provider.equals(user.getOauth2Provider()) && providerId.equals(user.getOauth2Id())) {
                    return;
                } else {
                    user.setOauth2Provider(provider);
                    user.setOauth2Id(providerId);
                    userRepository.save(user);
                    return;
                }
            } else {
                if (!user.isEnabled()) {
                    throw new RuntimeException(
                            "Account exists but is not activated."
                    );
                }

                user.setOauth2Provider(provider);
                user.setOauth2Id(providerId);
                user.setIsOauth2User(true);
                userRepository.save(user);
                return;
            }
        }

        User newUser = new User();
        String username = generateUsernameFromName(givenName, familyName, fullName, email);

        newUser.setUsername(username);
        newUser.setEmail(email);
        newUser.setPassword("");
        newUser.setOauth2Provider(provider);
        newUser.setOauth2Id(providerId);
        newUser.setIsOauth2User(true);
        newUser.setEnabled(true);
        newUser.setRole(Role.USER);
        newUser.setFailedAttempts(0);

        userRepository.save(newUser);
    }

    private String generateUsernameFromName(String givenName, String familyName,
                                            String fullName, String email) {

        String baseUsername;

        if (givenName != null && !givenName.trim().isEmpty() &&
                familyName != null && !familyName.trim().isEmpty()) {

            baseUsername = (givenName.trim() + familyName.trim())
                    .replaceAll("\\s+", "")
                    .replaceAll("[^a-zA-Z0-9]", "")
                    .toLowerCase();

        } else if (fullName != null && !fullName.trim().isEmpty()) {

            baseUsername = fullName.trim()
                    .replaceAll("\\s+", "")
                    .replaceAll("[^a-zA-Z0-9]", "")
                    .toLowerCase();

        } else {
            baseUsername = email.split("@")[0]
                    .replaceAll("[^a-zA-Z0-9]", "")
                    .toLowerCase();
        }

        if (baseUsername.isEmpty()) {
            baseUsername = "user";
        }

        if (baseUsername.length() > 20) {
            baseUsername = baseUsername.substring(0, 20);
        }

        String username = baseUsername;
        int counter = 1;

        while (userRepository.findByUsername(username).isPresent()) {
            username = baseUsername + counter;
            counter++;
        }

        return username;
    }
}
