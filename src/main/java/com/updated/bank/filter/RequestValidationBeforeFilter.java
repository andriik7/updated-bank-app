package com.updated.bank.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RequestValidationBeforeFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String header = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null) {
            header = header.trim();
        }

        if (StringUtils.startsWithIgnoreCase(header, "Basic ")) {
            byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(base64Token);
                String token = new String(decoded, StandardCharsets.UTF_8);
                int column = token.indexOf(":");
                if (column == -1) {
                    throw new BadCredentialsException("Invalid basic authentication token");
                }
                String email = token.substring(0, column);
                if (email.toLowerCase().contains("test")) {
                    httpResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }
            } catch (IllegalArgumentException ex) {
                throw new BadCredentialsException("Failed to decode authentication token");
            }
        }
        chain.doFilter(httpRequest, httpResponse);
    }
}
