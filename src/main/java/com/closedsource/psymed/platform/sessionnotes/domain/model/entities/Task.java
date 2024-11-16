package com.closedsource.psymed.platform.sessionnotes.domain.model.entities;


import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTaskCommand;
import jakarta.persistence.*;
import lombok.Getter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Entity
@EntityListeners(AuditingEntityListener.class)
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String title;

    @Column
    private String description;

    @Column
    private boolean completionStatus;

    protected Task() {
    }

    public Task(Long id, String title, String description, boolean completionStatus){
        this.id = id;
        this.title = title;
        this.description = description;
        this.completionStatus = completionStatus;
    }

    public Task(CreateTaskCommand createTaskCommand){
        this.title = createTaskCommand.title();
        this.description = createTaskCommand.description();
        this.completionStatus = createTaskCommand.completionStatus();
    }


}
