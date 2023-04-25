package com.example.AuthentificationService.sec.service;

import com.example.AuthentificationService.sec.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private AccountService accountService;

    public UserDetailsServiceImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //LOAD USER BY USERNAME
        AppUser appUser = accountService.loadUserByUsername(username);
        //INITIALIZE AN EMPTY COLLECTION FOR THE GRANTED AUTHORITIES
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        //ADDING USER'S ROLES TO THE LIST ENCAPSULATED IN SIMPLE-GRANTED-AUTHORITY CLASS CONSTRUCTOR
        appUser.getAppRoles().forEach(
                role -> authorities.add(
                        new SimpleGrantedAuthority(role.getRoleName())
                )
        );

        //Returning User [SPRING CLASS] which takes username, password and a list of GrantedAuthorities.
        return new User(
                appUser.getUsername(),
                appUser.getPassword(),
                authorities
        );
    }
}
