package com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTreatmentTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;
import jakarta.persistence.*;
import lombok.Getter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;
import java.util.List;

@Getter
@Entity
@EntityListeners(AuditingEntityListener.class)
public class TreatmentTask {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private Date date;

    @OneToMany
    @JoinColumn(name = "tasks")
    private List<Task> tasks;

    protected TreatmentTask(){}

    public TreatmentTask(String title, Date date, List<Task> tasks){
        this.title = title;
        this.date = date;
        this.tasks = tasks;
    }

    public TreatmentTask(CreateTreatmentTaskCommand command){
        this.title = command.title();
        this.date = command.date();
        this.tasks = command.tasks();
    }
}
