package org.example.controller;


import lombok.RequiredArgsConstructor;
import org.example.Entity.User;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-security-oauth2-example
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 10/01/18
 * Time: 16.06
 * To change this template use File | Settings | File Templates.
 */

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping(value = "/user_list")
    public List<User> listUser() {
        return userService.findAll();
    }

    @PostMapping(value = "/user_create")
    public User create(@RequestBody User user) {
        return userService.save(user);
    }

    @DeleteMapping(value = "/user/{id}")
    public String delete(@PathVariable(value = "id") Long id) {
        userService.delete(id);
        return "success";
    }

    @GetMapping("/hello")
    public String hello(OAuth2Authentication oauth) {
        return "Hello world " + oauth.getPrincipal();
    }

}
