package org.chypakk.controller;

import org.chypakk.model.User;
import org.chypakk.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;


@RestController
@RequestMapping("api")
public class TestController {

    @Autowired
    private UserService userService;

    @GetMapping("/test")
    public String test(){
        return "test";
    }

    @GetMapping("/users")
    public ResponseEntity<?> users(){
        List<User> users = userService.getAllUsers();

        return ResponseEntity.ok().body(users);
    }
}
