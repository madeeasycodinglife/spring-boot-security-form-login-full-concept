package com.madeeasy.security.event;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvent {
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent success) {
        // ...
        System.out.println("Success");
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failures) {
        // ...
        System.out.println("Failure");
    }

}
