package tech.devinhouse.copadomundo.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tech.devinhouse.copadomundo.exception.RegistroExistenteException;
import tech.devinhouse.copadomundo.models.Usuario;
import tech.devinhouse.copadomundo.repository.UsuarioRepository;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class UsuarioService implements UserDetailsService {
    private UsuarioRepository repo;
    private PasswordEncoder passwordEncoder;

    private String segredo ="LKSDHFLKADHFA894375864T8427KDSJHFDLKJGJA"; //Chave

    public Usuario criar(Usuario usuario) {
        boolean emailExistente = repo.existsUsuarioByEmail(usuario.getEmail());
        if (emailExistente)
            throw new RegistroExistenteException("Usuario", usuario.getEmail());
        String senhaCodificada = passwordEncoder.encode(usuario.getSenha());
        usuario.setSenha(senhaCodificada);
        usuario = repo.save(usuario);
        return usuario;
    }

    public List<Usuario> consultar() {
        return repo.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<Usuario> usuarioOpt = repo.findByEnail(email);
        if (usuarioOpt.isEmpty())
            throw new UsernameNotFoundException("Usuário não encontrado!");
        return usuarioOpt.get();
    }
    public String generateToken(Usuario usuario) {
        Algorithm algorithm = Algorithm.HMAC256(segredo.getBytes());
        String accessToken= JWT.create()
                .withSubject(usuario.getEmail())
                .withExpiresAt(new Date(System.currentTimeMillis()+10*60*6000))
                .withIssuer("Copa Do Mundo - API")
                .withClaim("roles",usuario.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        return accessToken;
    }



    /**
     * Extrai token do cabeçalho (header) Authorization.
     * @param authorizationHeader
     * @return String token JWT
     */
    public String getTokenFrom(String authorizationHeader){
        if (authorizationHeader == null|| !authorizationHeader.startsWith("Bearer "))
            throw new IllegalArgumentException("Invalid Headers");
        String token = authorizationHeader.substring("Bearer ".length());
        return token;
    }
    /**
     * Decodifica o token JWT e retorna um objeto que representa os dados constantes no token.
     * @param token
     * @return Token decodificado
     */

    public DecodedJWT getDecodedTokenFrom(String token){
        Algorithm algorithm =Algorithm.HMAC256(segredo.getBytes());
        JWTVerifier verifier= JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT;
    }


}
