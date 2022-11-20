package tech.devinhouse.copadomundo.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import tech.devinhouse.copadomundo.exception.RegistroExistenteException;
import tech.devinhouse.copadomundo.exception.RegistroNaoEncontradoException;
import tech.devinhouse.copadomundo.models.Jogador;
import tech.devinhouse.copadomundo.models.Selecao;
import tech.devinhouse.copadomundo.repository.JogadorRepository;
import tech.devinhouse.copadomundo.repository.SelecaoRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


@Service
@AllArgsConstructor
public class JogadorService {
    private JogadorRepository jogadorRepo;
    private SelecaoRepository selecaoRepo;


    public Jogador criar(String sigla, Jogador jogador) {
        Selecao selecao = selecaoRepo.findById(sigla)
                .orElseThrow(() -> new RegistroNaoEncontradoException(Selecao.class.getSimpleName(), sigla));
        final String nome = jogador.getNome();
        boolean existeComMesmoNomeNoMesmoTime = selecao.getJogadores().stream().anyMatch(p -> p.getNome().equals(nome));
        if (existeComMesmoNomeNoMesmoTime)
            throw new RegistroExistenteException(Jogador.class.getSimpleName(), nome);
        jogador.setSelecao(selecao);
        jogador = jogadorRepo.save(jogador);
        return jogador;
    }

    public List<Jogador> consultar(String sigla, String pesquisa) {
        Selecao selecao = selecaoRepo.findById(sigla)
                .orElseThrow(() -> new RegistroNaoEncontradoException(Selecao.class.getSimpleName(), sigla));
        List<Jogador> jogadores = selecao.getJogadores();
        if (pesquisa == null)
            return jogadores;
        List<Jogador> filtrados = new ArrayList<>();
        for(Jogador jogador : jogadores) {
            if (jogador.getNome().contains(pesquisa)) {
                filtrados.add(jogador);
            }
        }
        return filtrados;
    }

    public void excluir(String sigla, Integer idJogador) {
        Optional<Jogador> opt = jogadorRepo.findBySelecaoEidJogador(sigla, idJogador);
        if (opt.isEmpty())
            throw new RegistroNaoEncontradoException(Jogador.class.getSimpleName(), idJogador);
        jogadorRepo.deleteById(idJogador);
    }
}
