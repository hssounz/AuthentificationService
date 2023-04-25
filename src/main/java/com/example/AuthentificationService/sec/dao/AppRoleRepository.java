package com.example.AuthentificationService.sec.dao;


import com.example.AuthentificationService.sec.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;


public interface AppRoleRepository extends JpaRepository<AppRole, Long> {

    AppRole findByRoleName(String roleName);

}
