package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중 attemptAuthenctication");


        try{
//            BufferedReader br = request.getReader();
//
//            String input =  null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);
//            }

            ObjectMapper om = new ObjectMapper();
            User user=om.readValue(request.getInputStream(),User.class);
            System.out.println(user);

            //로그인 토큰만들기
            //DB에 있는 username과  password가 일치함
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //만든 토큰으로 로그인 시도
            //여기서 principalDetailsService가 실행됨, loadByUsername
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);
            log.info("authentication=={}", authentication);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            // 로그인이 정상적으로 되었다는뜼
            //권한처리때문에 session에 넣어줌
            log.info("principalDetails.getUser.getUsername== {}" , principalDetails.getUser().getUsername());

            return authentication;

        }catch (IOException e){
            e.printStackTrace();
        }

        return null;
    }


    //attemptAuthentication실행 후 인증이 정상적으로 되면 실행되는 함수
    //Jwt토큰을 만들어서 request요청한 사용자에게 Jwt토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
