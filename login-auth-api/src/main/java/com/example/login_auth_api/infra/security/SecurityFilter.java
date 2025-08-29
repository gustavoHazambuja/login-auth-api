package com.example.login_auth_api.infra.security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.login_auth_api.domain.User;
import com.example.login_auth_api.repositories.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    // Um filtro que vai executar uma vez a cada request
    // que chega na API

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException{
         var token = this.recoverToken(request);
         var login = tokenService.validadeToken(token);

         if(login != null){
            User user = userRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("User Not Found")); // Encontra o usuário pelo email
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")); // Faz  uma coleção de roles (papéis) que o usuário possui
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities); // Cria um objeto de autenticação
            SecurityContextHolder.getContext().setAuthentication(authentication);
         }

         filterChain.doFilter(request, response);
    }


    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization"); // Local onde está o token
        if(authHeader == null) return null;

        return authHeader.replace("Bearer", "");
        // Authorization : Bearer kdkdkfkdfkdfkdfkdkf --> kdkdkfkdfkdfkdfkdkf
            // Retorna apenas o valor do token
    }
    

}
