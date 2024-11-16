package com.closedsource.psymed.platform.sessionnotes.application.commandservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTreatmentTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TreatmentTaskCommandService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.TreatmentTaskRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TreatmentTaskCommandServiceImpl implements TreatmentTaskCommandService {

    private final TreatmentTaskRepository treatmentTaskRepository;

    public TreatmentTaskCommandServiceImpl(TreatmentTaskRepository treatmentTaskRepository){
        this.treatmentTaskRepository = treatmentTaskRepository;
    }


    @Override
    public Optional<TreatmentTask> handle(CreateTreatmentTaskCommand command) {

        var treatmentTask = new TreatmentTask(command);
        var result = treatmentTaskRepository.save(treatmentTask);

        return Optional.of(result);
    }
}
