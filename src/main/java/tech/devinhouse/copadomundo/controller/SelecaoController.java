package tech.devinhouse.copadomundo.controller;

import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.devinhouse.copadomundo.dto.SelecaoRequest;
import tech.devinhouse.copadomundo.dto.SelecaoResponse;
import tech.devinhouse.copadomundo.models.Selecao;
import tech.devinhouse.copadomundo.service.SelecaoService;

import javax.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

    @RestController
    @RequestMapping("api/v1/selecoes")
    @AllArgsConstructor
    public class SelecaoController{

        private SelecaoService service;
        private ModelMapper mapper;

        @PostMapping
        public ResponseEntity<SelecaoResponse> inserir(@RequestBody @Valid SelecaoRequest request) {
            Selecao selecao = mapper.map(request, Selecao.class);
            selecao = service.criar(selecao);
            SelecaoResponse resp = mapper.map(selecao, SelecaoResponse.class);
            return ResponseEntity.created(URI.create(resp.getSigla())).body(resp);
        }

        @GetMapping
        public ResponseEntity<List<SelecaoResponse>> consultar() {
            List<Selecao> lista = service.consultar();
            List<SelecaoResponse> resp = lista.stream().map(s -> mapper.map(s, SelecaoResponse.class)).collect(Collectors.toList());
            return ResponseEntity.ok(resp);
        }

        @GetMapping("{sigla}")
        public ResponseEntity<SelecaoResponse> consultar(@PathVariable("sigla") String sigla) {
            Selecao selecao = service.consultar(sigla);
            SelecaoResponse resp = mapper.map(selecao, SelecaoResponse.class);
            return ResponseEntity.ok(resp);
        }

        @PutMapping("{sigla}")
        public ResponseEntity<SelecaoResponse> atualizar(@PathVariable("sigla") String sigla, @RequestBody @Valid SelecaoRequest request) {
            Selecao selecao = mapper.map(request, Selecao.class);
            selecao = service.atualizar(selecao);
            SelecaoResponse resp = mapper.map(selecao, SelecaoResponse.class);
            return ResponseEntity.ok(resp);
        }

        @DeleteMapping("{sigla}")
        public ResponseEntity<SelecaoResponse> excluir(@PathVariable("sigla") String sigla) {
            service.excluir(sigla);
            return ResponseEntity.noContent().build();
        }

    }
