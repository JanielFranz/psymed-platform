package com.closedsource.psymed.platform.sessionnotes.application.commandservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateProfessionalTreatmentTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.service.ProfessionalTreatmentTaskCommandService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.ProfessionalTreatmentTaskRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ProfessionalTreatmentTaskCommandServiceImpl implements ProfessionalTreatmentTaskCommandService {

    private ProfessionalTreatmentTaskRepository professionalTreatmentTaskRepository;

    public ProfessionalTreatmentTaskCommandServiceImpl(ProfessionalTreatmentTaskRepository professionalTreatmentTaskRepository){
        this.professionalTreatmentTaskRepository = professionalTreatmentTaskRepository;
    }

    @Override
    public Optional<ProfessionalTreatmentTask> handle(CreateProfessionalTreatmentTaskCommand command) {

        var professionalTreatmentTask = new ProfessionalTreatmentTask(command);
        var result = professionalTreatmentTaskRepository.save(professionalTreatmentTask);

        return Optional.of(result);
    }
}
