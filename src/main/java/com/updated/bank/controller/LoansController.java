package com.updated.bank.controller;

import com.updated.bank.model.Customer;
import com.updated.bank.model.Loans;
import com.updated.bank.repository.CustomerRepository;
import com.updated.bank.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoansController {

    private final LoanRepository loanRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myLoans")
    public List<Loans> getLoanDetails(@RequestParam String email) {
        Customer customer = customerRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer doesn't exist"));
        return loanRepository.findByCustomerIdOrderByStartDtDesc(customer.getId());
    }

}
