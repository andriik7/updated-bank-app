package com.updated.bank.controller;

import com.updated.bank.model.Accounts;
import com.updated.bank.model.Customer;
import com.updated.bank.repository.AccountsRepository;
import com.updated.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AccountController {

    private final AccountsRepository accountsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myAccount")
    public Accounts getAccountDetails(@RequestParam String email) {
        Customer customer = customerRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer with such an email is not found!"));
        return accountsRepository.findByCustomerId(customer.getId()).orElseThrow(() -> new IllegalArgumentException("Current customer has not associated accounts"));
    }


}
