package com.updated.bank.controller;

import com.updated.bank.model.Customer;
import com.updated.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    @Autowired
    private CustomerRepository repository;
    @Autowired
    private PasswordEncoder encoder;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Customer customer) {
        try {
            String hashPwd = encoder.encode(customer.getPwd());
            customer.setPwd(hashPwd);
            Customer saved = repository.save(customer);
            if (saved.getId() > 0) {
                return ResponseEntity.status(HttpStatus.CREATED)
                        .body("Given customer was successfully saved");
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Customer wasn't created due to bad request");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An exception occurred: " + e.getMessage());
        }
    }
}
