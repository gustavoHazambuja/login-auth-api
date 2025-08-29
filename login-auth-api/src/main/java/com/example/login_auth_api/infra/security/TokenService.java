package com.example.login_auth_api.infra.security;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.login_auth_api.domain.User;

@Service
public class TokenService {

    @Value("${api.security.toke.secret}")
    private String secret;
    
    public String generateToken(User user){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret); // Define o algoritmo de criptografia

            String token = JWT.create()
                    .withIssuer("login-auth-api") // Quem emite o token
                    .withSubject(user.getEmail()) // Quem recebe o token
                    .withExpiresAt(this.generateExpirationDate()) // Tempo de expiração
                    .sign(algorithm); 

                return token;    

        }catch(JWTCreationException exception){
            throw new RuntimeException("Error while authenticating");
        }
    }

    public String validadeToken(String token){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret); // Define o algoritmo de criptografia
            return JWT.require(algorithm)
                    .withIssuer("login-auth-api")
                    .build() // Constrói o objeto para fazer a verificação
                    .verify(token) // Verifica o token
                    .getSubject(); // Pega o valor gerado do token
        }catch(JWTVerificationException exception){
            return null;
        }
    }


     private Instant generateExpirationDate(){
            return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
        }
}
