package io.security.BasicSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration  // 설정 클래스이므로
@EnableWebSecurity  // 인증, 인가 관련 설정 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    // 인증
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()   // 어떤 요청에도 인증이 필요하다.
            .and()
                .formLogin()
                    //.loginPage("/user/login")           // template 커스터마이징
                    .defaultSuccessUrl("/")                 // 성공시 어디로갈까?
                    .failureUrl("/user/login")           // 실패시 어디로갈까?
                    .usernameParameter("userId")            // name = "userId"
                    .passwordParameter("passwd")            // name = "passwd"
                    .loginProcessingUrl("/login")      // action url
                    .successHandler(new CustomSuccessHandler())
                    .failureHandler(new CustomFailureHandler())
                    .permitAll()   // 로그인 경로는 권한 모두 허용
            .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/")
                    .addLogoutHandler(new CustomLogoutHandler())
                    .logoutSuccessHandler(new CustomLogoutSuccessHandler())
                    .deleteCookies("remember-me")
            .and()
                .rememberMe()
                    .rememberMeParameter("remember")    // name = "remember"
                    .tokenValiditySeconds(3600)         // 유지 시간
                    .alwaysRemember(false)
                    .userDetailsService(userDetailsService)
            .and()
                .sessionManagement()
                    .sessionFixation().changeSessionId()    // 세션 보호
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .maximumSessions(1) // 최대 세션 갯수 적용
                    .maxSessionsPreventsLogin(true)    // 세션 최대일 경우 로그인 막아보리기
            ;
    }

    // 인가
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // {noop} password 유형. password 인코더 암호화 방식이다.
        // 테스트용 정적 생성 방식
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }
}
