package com.example.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@RestController
@RequestMapping("/users")
public class UserController {


    @GetMapping("/{id}")
    @RolesAllowed({"scope_read"})
    public String get(@PathVariable Long id){
        return "get user admin  by id: " + id;
    }
}
