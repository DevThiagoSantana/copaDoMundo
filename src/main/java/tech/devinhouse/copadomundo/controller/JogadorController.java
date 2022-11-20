package tech.devinhouse.copadomundo.controller;


import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.devinhouse.copadomundo.dto.JogadorRequest;
import tech.devinhouse.copadomundo.dto.JogadorResponse;
import tech.devinhouse.copadomundo.models.Jogador;
import tech.devinhouse.copadomundo.service.JogadorService;

import javax.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("api/v1/selecoes/{sigla}/jogadores")
@AllArgsConstructor
public class JogadorController {
    private JogadorService service;
    private ModelMapper mapper;

    @PostMapping
    public ResponseEntity<JogadorResponse> criar(@PathVariable("sigla") String sigla, @RequestBody @Valid JogadorRequest request) {
        Jogador jogador = mapper.map(request, Jogador.class);
        jogador = service.criar(sigla, jogador);
        JogadorResponse resp = mapper.map(jogador, JogadorResponse.class);
        return ResponseEntity.created(URI.create(resp.getId().toString())).body(resp);
    }

    @GetMapping
    public ResponseEntity<List<JogadorResponse>> listar(@PathVariable("sigla") String sigla,
                                                        @RequestParam(value = "nome", required = false) String nomePesquisa) {
        List<Jogador> jogadores = service.consultar(sigla, nomePesquisa);
        List<JogadorResponse> resp = jogadores.stream().map(p -> mapper.map(p, JogadorResponse.class)).collect(Collectors.toList());
        return ResponseEntity.ok(resp);
    }

    @DeleteMapping("{id}")
    public ResponseEntity<JogadorResponse> excluir(@PathVariable("sigla") String sigla, @PathVariable("id") Integer id) {
        service.excluir(sigla, id);
        return ResponseEntity.noContent().build();
    }


}
