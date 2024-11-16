package com.closedsource.psymed.platform.sessionnotes.application.queryservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllProfessionalTreatmentTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetProfessionalTreatmentTaskByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.ProfessionalTreatmentTaskQueryService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.ProfessionalTreatmentTaskRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ProfessionalTreatmentQueryServiceImpl implements ProfessionalTreatmentTaskQueryService {

    private final ProfessionalTreatmentTaskRepository professionalTreatmentTaskRepository;

    public ProfessionalTreatmentQueryServiceImpl(ProfessionalTreatmentTaskRepository professionalTreatmentTaskRepository) {
        this.professionalTreatmentTaskRepository = professionalTreatmentTaskRepository;
    }

    @Override
    public List<ProfessionalTreatmentTask> handle(GetAllProfessionalTreatmentTaskQuery query) {
        return professionalTreatmentTaskRepository.findAll();
    }

    @Override
    public Optional<ProfessionalTreatmentTask> handle(GetProfessionalTreatmentTaskByIdQuery query) {
        return professionalTreatmentTaskRepository.findById(query.id());
    }
}
