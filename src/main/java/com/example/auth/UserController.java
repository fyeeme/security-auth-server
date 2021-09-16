package com.example.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

@RestController
//@RequestMapping("/")
public class UserController {
    public static final Logger log = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/users/{id}")
    //必须以ROLE_开头，否则会自定拼接ROLE_
    @RolesAllowed({"ROLE_read"})
    public String get(@PathVariable Long id) {
        return "get user admin  by id: " + id;
    }

    @GetMapping("/authorized")
    @PermitAll
    public String authorized(@RequestParam String code) {
        log.info("authorized:{}", code);
        return code;
    }

}
