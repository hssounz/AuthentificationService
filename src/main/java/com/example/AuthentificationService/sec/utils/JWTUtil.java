package com.example.AuthentificationService.sec.utils;

public class JWTUtil {
    public static final String JWT_SECRET="25442A472D4B6150645367566B58703273357638792F423F4528482B4D625165";
    public static final String AUTHORIZATION_HEADER="Authorization";
    public static final String PREFIX = "Bearer ";
    public static final Long EXP_ACCESS_TOKEN = 15 * 60 * 1000L;
    public static final Long EXP_REFRESH_TOKEN = 60 * 60 * 1600 * 1000L;
}
