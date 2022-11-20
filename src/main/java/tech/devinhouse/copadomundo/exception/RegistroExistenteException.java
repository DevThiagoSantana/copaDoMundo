package tech.devinhouse.copadomundo.exception;

public class RegistroExistenteException extends RuntimeException {

    public RegistroExistenteException(String nomeRecurso, String id) {
        super(nomeRecurso + " com identificador " + id + " já existente!");
    }

    public RegistroExistenteException(String nomeRecurso, Long id) {
        this(nomeRecurso, String.valueOf(id));
    }

    public RegistroExistenteException(String nomeRecurso, Integer id) {
        this(nomeRecurso, String.valueOf(id));
    }

}
