package com.closedsource.psymed.platform.sessionnotes.domain.model.entities;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateNoteCommand;
import jakarta.persistence.*;
import lombok.Getter;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Entity
@EntityListeners(AuditingEntityListener.class)
public class Note extends AbstractAggregateRoot<Note> {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    @Column(length = 200)
    private String description;

    @Column(length = 40)
    private String symptoms;

    public Note(CreateNoteCommand createNoteCommand) {
        this.symptoms = createNoteCommand.symptom();
        this.description = createNoteCommand.description();
    }

    protected Note(){

    }
}
