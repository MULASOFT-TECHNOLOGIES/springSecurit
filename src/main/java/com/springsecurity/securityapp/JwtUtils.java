package com.springsecurity.securityapp;
 
import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
    private static Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;
    
    @Value("${spring.app.ExpirationMs}")
    private Long ExpirationMs;

    public String getJwtToken(HttpServletRequest  request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug(bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);  
        }
        
        return null;
    }
 
    public String generateJwtToken(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + ExpirationMs))
                .signWith(key())
                .compact();
        
    }

    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUsername(String token){
       return Jwts.parser()
              .verifyWith((SecretKey) key())
              .build()
              .parseSignedClaims(token)
              .getPayload()
              .getSubject();
    }

    public boolean ValidatingJwtToken(String token){
       try{
             Jwts.parser()
             .verifyWith((SecretKey) key())
             .build()
             .parseSignedClaims(token);
           return true ;
       }catch(MalformedJwtException e){
         logger.error("invalid jwt Token" + e.getMessage());
       }catch(ExpiredJwtException e){
        logger.error("invalid jwt Token time Expired" + e.getMessage());
       }catch(UnsupportedJwtException e){
        logger.error("invalid jwt Token Unsupported" + e.getMessage());
       }catch(IllegalArgumentException e){
        logger.error("Illegal  jwt Token" + e.getMessage());
       }
      
      return false;
    }
}
