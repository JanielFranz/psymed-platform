package com.closedsource.psymed.platform.clinicalhistory.application.internal.commandservices;

import com.closedsource.psymed.platform.clinicalhistory.domain.model.aggregates.ClinicalHistory;
import com.closedsource.psymed.platform.clinicalhistory.domain.model.commands.CreateClinicalHistoryCommand;
import com.closedsource.psymed.platform.clinicalhistory.domain.service.ClinicalHistoryCommandService;
import com.closedsource.psymed.platform.clinicalhistory.infrastructure.persistence.jpa.repositories.ClinicalHistoryRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ClinicalHistoryCommandServiceImpl implements ClinicalHistoryCommandService {

    private final ClinicalHistoryRepository clinicalHistoryRepository;

    public ClinicalHistoryCommandServiceImpl(ClinicalHistoryRepository clinicalHistoryRepository) {
        this.clinicalHistoryRepository = clinicalHistoryRepository;
    }

    @Override
    public Optional<ClinicalHistory> handle(CreateClinicalHistoryCommand command) {

        ClinicalHistory clinicalHistory = new ClinicalHistory(command);

        // patient.updateClinicalHistoryStatus();

        var clinicalHistorySaved = this.clinicalHistoryRepository.save(clinicalHistory);
        return Optional.of(clinicalHistorySaved);
    }
}
