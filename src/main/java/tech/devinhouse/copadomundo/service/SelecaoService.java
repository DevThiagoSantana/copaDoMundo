package tech.devinhouse.copadomundo.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import tech.devinhouse.copadomundo.exception.RegistroExistenteException;
import tech.devinhouse.copadomundo.exception.RegistroNaoEncontradoException;
import tech.devinhouse.copadomundo.models.Selecao;
import tech.devinhouse.copadomundo.repository.SelecaoRepository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class SelecaoService {

    private SelecaoRepository repo;
    public Selecao criar(Selecao selecao) {
        if (repo.existsById(selecao.getSigla()))
            throw  new RegistroExistenteException(Selecao.class.getSimpleName(),selecao.getSigla());
        selecao.setDataCadastro(LocalDateTime.now());
        selecao = repo.save(selecao);
        return selecao;
    }


    public List<Selecao> consultar() {
        List<Selecao>selecoes =repo.findAll();
        return selecoes;
    }

    public Selecao consultar(String sigla) {
        Optional<Selecao> opt = repo.findById(sigla);
        return opt.orElseThrow(() -> new RegistroNaoEncontradoException(Selecao.class.getSimpleName(), sigla));
    }

    public Selecao atualizar(Selecao selecao) {
        final String sigla = selecao.getSigla();
        Selecao selecaoBD = repo.findById(sigla)
                .orElseThrow(() -> new RegistroNaoEncontradoException(Selecao.class.getSimpleName(), sigla));
        selecaoBD.setGrupo(selecao.getGrupo());
        selecaoBD.setNome(selecao.getNome());
        selecao = repo.save(selecaoBD);
        return selecao;
    }

    public void excluir(String sigla) {
        if (!repo.existsById(sigla))
            throw new RegistroNaoEncontradoException(Selecao.class.getSimpleName(), sigla);
        repo.deleteById(sigla);
    }

}
