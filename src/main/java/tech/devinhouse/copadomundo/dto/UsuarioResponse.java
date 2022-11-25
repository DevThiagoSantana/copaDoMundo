package tech.devinhouse.copadomundo.dto;

import lombok.Data;
import tech.devinhouse.copadomundo.models.Papel;

import java.time.LocalDate;
import java.util.List;

@Data
public class UsuarioResponse {

    private Integer id;

    private String email;

    private LocalDate dataNascimento;

    private List<Papel> papeis;
}
