package com.closedsource.psymed.platform.clinicalhistory.application.internal.queryservices;

import com.closedsource.psymed.platform.clinicalhistory.domain.model.aggregates.ClinicalHistory;
import com.closedsource.psymed.platform.clinicalhistory.domain.model.queries.GetClinicalHistoryByIdQuery;
import com.closedsource.psymed.platform.clinicalhistory.domain.model.queries.GetClinicalHistoryByPatientIdQuery;
import com.closedsource.psymed.platform.clinicalhistory.domain.service.ClinicalHistoryQueryService;
import com.closedsource.psymed.platform.clinicalhistory.infrastructure.persistence.jpa.repositories.ClinicalHistoryRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ClinicalHistoryQueryServiceImpl implements ClinicalHistoryQueryService {
    private final ClinicalHistoryRepository clinicalHistoryRepository;
    public ClinicalHistoryQueryServiceImpl(ClinicalHistoryRepository clinicalHistoryRepository) {
        this.clinicalHistoryRepository = clinicalHistoryRepository;
    }
    @Override
    public Optional<ClinicalHistory> handle(GetClinicalHistoryByIdQuery query) {
        return this.clinicalHistoryRepository.findById(query.clinicalHistoryId());
    }
    @Override
    public Optional<ClinicalHistory> handle(GetClinicalHistoryByPatientIdQuery query) {
        return this.clinicalHistoryRepository.findById(query.patientId());
    }
}
