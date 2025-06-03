package org.chypakk.keyGenerator;

import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

public class Test {
    public static void main(String[] args) throws IOException {
        var test = new ClassPathResource("private.pem").getFile().toPath();
        System.out.println(test);
    }
}
