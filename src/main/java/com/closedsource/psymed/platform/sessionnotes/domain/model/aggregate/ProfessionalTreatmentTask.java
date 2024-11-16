package com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateProfessionalTreatmentTaskCommand;
import jakarta.persistence.*;
import lombok.Getter;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.List;

@Getter
@Entity
@EntityListeners(AuditingEntityListener.class)
public class ProfessionalTreatmentTask {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToMany
    @JoinColumn(name = "treatment_task")
    private List<TreatmentTask> treatmentTasks;

    protected ProfessionalTreatmentTask(){}


    public ProfessionalTreatmentTask(CreateProfessionalTreatmentTaskCommand command){
        this.treatmentTasks = command.treatmentTasks();
    }
}
