package tech.devinhouse.copadomundo.dto;

import lombok.Data;

import java.util.Map;

@Data
public class ErroResponse {

    private String mensagem;

    private Map<String, String> details;

    public ErroResponse(String mensagem) {
        this.mensagem = mensagem;
    }

    public ErroResponse(String mensagem, Map<String, String> details) {
        this(mensagem);
        this.details = details;
    }

}