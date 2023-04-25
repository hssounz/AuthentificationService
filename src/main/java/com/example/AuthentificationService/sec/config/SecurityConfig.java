package com.example.AuthentificationService.sec.config;

import com.example.AuthentificationService.sec.filters.JwtAuthenticationFilter;
import com.example.AuthentificationService.sec.filters.JwtAuthorizationFilter;
import com.example.AuthentificationService.sec.service.AccountService;
import com.example.AuthentificationService.sec.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration @EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private AccountService accountService;
    private UserDetailsServiceImpl userDetailsService;
    public SecurityConfig(AccountService accountService, UserDetailsServiceImpl userDetailsService) {
        this.accountService = accountService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //Disabling CSRF Protection for stateless auth
        http.csrf().disable();
        //Enabling stateless auth
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //disabling HTML frames from being blocked [FOR H2-CONSOLE]
        http.headers().frameOptions().disable();
        //White List:
        http.authorizeRequests().antMatchers(
                "/h2-console/**",
                "/refreshToken/**",
                "/login/**"
        ).permitAll();

        //ALLOWS ADMIN TO POST AND USER ONLY TO GET:
//        http.authorizeRequests().antMatchers(HttpMethod.POST, "/users/**").hasAuthority("ADMIN");
//        http.authorizeRequests().antMatchers(HttpMethod.GET, "/users/**").hasAuthority("USER");

        //Forbid all the request to none authenticated users
        http.authorizeRequests().anyRequest().authenticated();

        //JWT FILTERS
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
