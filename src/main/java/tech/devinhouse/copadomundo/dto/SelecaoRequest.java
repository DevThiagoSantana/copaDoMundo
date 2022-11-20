package tech.devinhouse.copadomundo.dto;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

@Data
public class SelecaoRequest {

    @NotEmpty(message = "{campo.obrigatorio}")
    @Size(min = 1, max = 3,message = "{campo.invalido}")
    private String sigla;

    @NotEmpty(message = "{campo.obrigatorio}")
    @Size(min = 1, max = 40,message = "{campo.invalido}")
    private String nome;

    @NotEmpty(message = "{campo.obrigatorio}")
    @Size(min = 1, max = 1,message = "{campo.invalido}")
    private String grupo;

}
