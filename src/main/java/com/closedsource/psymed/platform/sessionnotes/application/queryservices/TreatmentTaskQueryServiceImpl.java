package com.closedsource.psymed.platform.sessionnotes.application.queryservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllTreatmentTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetTreatmentTaskByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TreatmentTaskQueryService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.TreatmentTaskRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class TreatmentTaskQueryServiceImpl implements TreatmentTaskQueryService {

    private final TreatmentTaskRepository treatmentTaskRepository;

    public TreatmentTaskQueryServiceImpl(TreatmentTaskRepository treatmentTaskRepository) {
        this.treatmentTaskRepository = treatmentTaskRepository;
    }

    @Override
    public List<TreatmentTask> handle(GetAllTreatmentTaskQuery query) {
        return treatmentTaskRepository.findAll();
    }

    @Override
    public Optional<TreatmentTask> handle(GetTreatmentTaskByIdQuery query) {
        return treatmentTaskRepository.findById(query.id());
    }
}
