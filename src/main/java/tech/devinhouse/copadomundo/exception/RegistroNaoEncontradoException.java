package tech.devinhouse.copadomundo.exception;

public class RegistroNaoEncontradoException extends RuntimeException {
    public RegistroNaoEncontradoException(String nomeRecurso, String id) {
        super(nomeRecurso + " com identificador " + id + " não encontrado!");
    }

    public RegistroNaoEncontradoException(String nomeRecurso, Integer id) {
        this(nomeRecurso, String.valueOf(id));
    }
}
