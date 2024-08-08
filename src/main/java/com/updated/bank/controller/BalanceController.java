package com.updated.bank.controller;

import com.updated.bank.model.AccountTransactions;
import com.updated.bank.model.Customer;
import com.updated.bank.repository.AccountTransactionsRepository;
import com.updated.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class BalanceController {

    private final AccountTransactionsRepository accountTransactionsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myBalance")
    public List<AccountTransactions> getBalanceDetails(@RequestParam String email) {
        Customer customer = customerRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer doesn't exist"));
        return accountTransactionsRepository.findByCustomerIdOrderByTransactionDtDesc(customer.getId());
    }
}
