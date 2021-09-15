package com.example.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.RolesAllowed;

@RestController
//@RequestMapping("/")
public class UserController {
    public static final Logger log = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/users/{id}")
    @RolesAllowed({"ROLE_scope_read"})
    public String get(@PathVariable Long id) {
        return "get user admin  by id: " + id;
    }

    @GetMapping("/authorized")
    public String authorized(@RequestParam String code) {
        log.info("authorized:{}", code);
        return code;
    }

}
