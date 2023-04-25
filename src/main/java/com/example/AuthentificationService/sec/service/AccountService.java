package com.example.AuthentificationService.sec.service;

import com.example.AuthentificationService.sec.entities.AppRole;
import com.example.AuthentificationService.sec.entities.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();

}
