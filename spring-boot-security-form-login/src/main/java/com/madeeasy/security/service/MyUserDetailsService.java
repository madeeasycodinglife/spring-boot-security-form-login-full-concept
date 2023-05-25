package com.madeeasy.security.service;

import com.madeeasy.entity.Customer;
import com.madeeasy.entity.Roles;
import com.madeeasy.repository.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private CustomerRepository customerRepository;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Customer customer = customerRepository.findByEmail(email);
        if (customer== null){
            throw new UsernameNotFoundException("User not found");
        }
        return new User(
                customer.getEmail(),
                customer.getPassword(),
                this.authorities(customer.getRoles())
        );
    }

    private Collection<? extends GrantedAuthority> authorities(Set<Roles> roles) {
        List<SimpleGrantedAuthority> simpleGrantedAuthorityList = roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());
        return simpleGrantedAuthorityList;
    }
}
