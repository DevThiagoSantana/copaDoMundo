package tech.devinhouse.copadomundo.dto;

import lombok.Data;
import tech.devinhouse.copadomundo.models.Posicao;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Data
public class JogadorRequest {

    @NotEmpty(message = "{campo.obrigatorio}")
    @Size(min = 1,max = 30, message = "{campo.invalido}")
    private String nome;

    @NotEmpty(message = "{campo.obrigatorio}")
    @Pattern(regexp = "GOLEIRO|ZAGUEIRO|VOLANTE|LATERAL|MEIO_CAMPISTA|ATACANTE",flags = Pattern.Flag.CASE_INSENSITIVE,message = "{campo.invalido}")
    private String posicao;

    public Posicao obterPosicao(){
        return Posicao.valueOf(this.posicao);
    }
}
