package co.lab6_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class Lab6SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(Lab6SecurityApplication.class, args);
    }

}
