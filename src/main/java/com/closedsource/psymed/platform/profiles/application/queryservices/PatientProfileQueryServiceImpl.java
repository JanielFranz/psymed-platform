package com.closedsource.psymed.platform.profiles.application.queryservices;

import com.closedsource.psymed.platform.profiles.domain.model.aggregates.PatientProfile;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetAllPatientProfilesQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetClinicalHistoryIdByPatientIdQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetPatientProfileByIdQuery;
import com.closedsource.psymed.platform.profiles.domain.services.PatientProfileQueryService;
import com.closedsource.psymed.platform.profiles.infrastructure.persistence.jpa.repositories.PatientProfileRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PatientProfileQueryServiceImpl implements PatientProfileQueryService {

    private final PatientProfileRepository patientProfileRepository;

    public PatientProfileQueryServiceImpl (PatientProfileRepository patientProfileRepository) {
        this.patientProfileRepository = patientProfileRepository;
    }

    @Override
    public Optional<PatientProfile> handle(GetPatientProfileByIdQuery query) {
        return patientProfileRepository.findById(query.id());
    }

    @Override
    public List<PatientProfile> handle(GetAllPatientProfilesQuery query) {
        return patientProfileRepository.findAll();
    }

    @Override
    public Long handle(GetClinicalHistoryIdByPatientIdQuery query) {
        return patientProfileRepository.findClinicalHistoryIdById(query.patientId());
    }
}
