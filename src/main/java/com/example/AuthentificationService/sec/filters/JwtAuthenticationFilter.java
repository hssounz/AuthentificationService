package com.example.AuthentificationService.sec.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.AuthentificationService.sec.utils.JWTUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //RECUPERATE CREDENTIALS
        String username = request.getHeader("username");
        String password = request.getHeader("password");

        //Creating UsernamePasswordAuthentificationToken : which will be provided for the authentication manager
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        //Returning an Authentication
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        //EXTRACT USER FROM AUTH RESULT -> from "attemptAuth"
        User user =(User) authResult.getPrincipal();

        //generate access token - cour durée
        String jwtAccessToken = JWT
                .create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() +JWTUtil.EXP_ACCESS_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .withClaim(
                        "role",
                        user.getAuthorities()
                                .stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(getAlgorithm());

        //generate refresh token - longue durée
        String jwtRefreshToken = JWT
                .create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXP_REFRESH_TOKEN))
                .withIssuer(request.getRequestURL().toString())
                .sign(getAlgorithm());

        //Create a map with both tokens
        Map<String, String> idToken = new HashMap<>();
        idToken.put("access-token", jwtAccessToken);
        idToken.put("refresh-token", jwtRefreshToken);

        //Parse Into JSON To the response body
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(), idToken);
    }

    public Algorithm getAlgorithm() {
        return Algorithm.HMAC256(JWTUtil.JWT_SECRET);
    }


}
