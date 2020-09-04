package pl.gregorymartin.jwtapp1;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

@Service
class JwtTokenFilter extends OncePerRequestFilter {
    private static RsaUtil rsaUtil;

    public JwtTokenFilter() {
        rsaUtil = new RsaUtil();
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final FilterChain filterChain) throws ServletException, IOException {
        String token = httpServletRequest.getHeader("Authorization");
        UsernamePasswordAuthenticationToken authenticationToken
                = getAuthenticationToken(token.substring(7));


        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    private static UsernamePasswordAuthenticationToken getAuthenticationToken( final String token) {
        try {
            RSAPublicKey publicKey = rsaUtil.readFilePublicKey("keys/public_key.txt");
            Algorithm algorithm = Algorithm.RSA512(publicKey, null);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("name", "chuj")
                    .withClaim("admin", true)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            String name = jwt.getClaims().get("name").asString();
            boolean admin = jwt.getClaims().get("admin").asBoolean();
            String role = "ROLE_USER";
            if(admin)
                role = "ROLE_ADMIN";

            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);
            return new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(authority));
        } catch (JWTVerificationException x) {
            throw x;
        }
    }
}
