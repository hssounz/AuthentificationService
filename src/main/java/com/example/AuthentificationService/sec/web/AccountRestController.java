package com.example.AuthentificationService.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.AuthentificationService.sec.entities.AppRole;
import com.example.AuthentificationService.sec.entities.AppUser;
import com.example.AuthentificationService.sec.service.AccountService;
import com.example.AuthentificationService.sec.utils.JWTUtil;
import com.example.AuthentificationService.sec.utils.UserRoleAttributes;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController @RequiredArgsConstructor
public class AccountRestController {

    private final AccountService accountService;

    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers()
    {
        return accountService.listUsers();
    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser)
    {
        return accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole)
    {
        return accountService.addNewRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody UserRoleAttributes attributes)
    {
        accountService.addRoleToUser(attributes.getUsername(), attributes.getRoleName());
    }

    @GetMapping("/profile")
    public AppUser profile(Principal principal) {
        return accountService.loadUserByUsername(principal.getName());
    }

    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        //EXTRACT BEARER TOKEN
        String refreshToken = request.getHeader(JWTUtil.AUTHORIZATION_HEADER);
        //CHECK IF ITS A VALID TOKEN
        if (refreshToken != null && refreshToken.startsWith(JWTUtil.PREFIX)) {
            try{
                String jwt = refreshToken.substring(JWTUtil.PREFIX.length());

                //CREATE HMAC CRYPTO ALGO
                Algorithm algorithm =
                        Algorithm
                                .HMAC256(JWTUtil.JWT_SECRET);

                //DECODE JWT
                DecodedJWT decodedJWT = JWT
                        .require(algorithm)
                        .build()
                        .verify(jwt);

                //Load User from decoded JWT
                AppUser appUser = accountService
                        .loadUserByUsername(
                                decodedJWT.getSubject()
                        );

                //generate access token
                String jwtAccessToken = JWT
                        .create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXP_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim(
                                "role",
                                appUser
                                        .getAppRoles()
                                        .stream().map(AppRole::getRoleName)
                                        .collect(Collectors.toList())
                                )
                        .sign(algorithm);

                //Create a map with both tokens
                Map<String, String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", refreshToken);

                //Parse Into JSON To the response body
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);

            } catch (RuntimeException e){
                //SET ERROR MESSAGE IN RESPONSE HEADER
                response.setHeader("error-message", e.getMessage());
                //SEND 403 HTTP CODE
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                throw e;
            }
        } else {
                throw new RuntimeException("Incorrect Refresh Token");
        }

    }
}
