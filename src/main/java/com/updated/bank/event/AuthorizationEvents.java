package com.updated.bank.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthorizationEvents {

    @EventListener
    public void onFailure(AuthorizationDeniedEvent deniedEvent) {
        log.error("Authorization failed for user : {} with authorities : {} | due to : {}",
                deniedEvent.getAuthentication().get().getName(),
                deniedEvent.getAuthentication().get().getAuthorities(),
                deniedEvent.getAuthorizationDecision().toString());
    }
}