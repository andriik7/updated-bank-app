package com.updated.bank.controller;

import com.updated.bank.model.Cards;
import com.updated.bank.model.Customer;
import com.updated.bank.repository.CardsRepository;
import com.updated.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class CardsController {

    private final CardsRepository cardsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myCards")
    //@PostFilter("filterObject.customerId != 1")
    public List<Cards> getCardDetails(@RequestParam String email) {
        Customer customer = customerRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer doesn't exist"));
        return cardsRepository.findByCustomerId(customer.getId());
    }
}
