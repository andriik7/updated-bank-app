package com.updated.bank.controller;

import com.updated.bank.model.Cards;
import com.updated.bank.model.Customer;
import com.updated.bank.repository.CardsRepository;
import com.updated.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
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
    public List<Cards> getCardDetails(@RequestParam long id, Authentication authentication) {
        String email = authentication.getName();
        Customer customer = customerRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Customer doesn't exist"));
        if (customer.getId() != id) {
            throw new AccessDeniedException("Customer is not allowed to access endpoint");
        }
        List<Cards> cards = cardsRepository.findByCustomerId(id);
        return cards;
    }
}
