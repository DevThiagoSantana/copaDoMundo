package tech.devinhouse.copadomundo.models;

import lombok.Data;
import lombok.Generated;

import javax.persistence.*;

@Entity
@Table(name = "JOGADORES")
@Data
public class Jogador {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID_JOGADOR")
    private Integer id;

    private String Nome;

    @Enumerated(EnumType.STRING)
    private Posicao posicao;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "sigla", referencedColumnName = "sigla")
    private Selecao selecao;






}
