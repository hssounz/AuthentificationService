package com.example.AuthentificationService.sec.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.AuthentificationService.sec.utils.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        if (request.getServletPath().equals("/refreshToken")) {
            filterChain.doFilter(request, response);
        } else {

            //EXTRACT BEARER TOKEN
            String authorizationToken = request.getHeader(JWTUtil.AUTHORIZATION_HEADER);
            //CHECK IF ITS A VALID TOKEN
            if (authorizationToken != null && authorizationToken.startsWith(JWTUtil.PREFIX)) {
                try{
                    String jwt = authorizationToken.substring(JWTUtil.PREFIX.length());

                    //CREATE HMAC CRYPTO ALGO
                    Algorithm algorithm = Algorithm.HMAC256(JWTUtil.JWT_SECRET);

                    //BUILD THE JWT-VERIFIER
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                    //DECODE JWT
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);

                    //EXTRACT USERNAME
                    String username = decodedJWT.getSubject();

                    //EXTRACT ROLES
                    String[] roles = decodedJWT.getClaim("role").asArray(String.class);

                    //CONVERT ROLES TO GRANTED AUTHORITIES
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String role : roles)
                        authorities.add(new SimpleGrantedAuthority(role));

                    //GET USERNAME-PASSWORD-AUTH-TOKEN For SecurityContextHolder
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    //AUTHENTICATE USER WITH CONTEXT HOLDER
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    filterChain.doFilter(request, response);
                } catch (RuntimeException e){
                    //SET ERROR MESSAGE IN RESPONSE HEADER
                    response.setHeader("error-message", e.getMessage());
                    //SEND 403 HTTP CODE
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                    throw e;
                }
            } else {
                //USER STAY UNKNOWN
                filterChain.doFilter(request, response);
            }

        }
    }
}
