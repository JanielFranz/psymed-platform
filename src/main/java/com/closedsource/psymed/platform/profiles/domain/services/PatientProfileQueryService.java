package com.closedsource.psymed.platform.profiles.domain.services;

import com.closedsource.psymed.platform.profiles.domain.model.aggregates.PatientProfile;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetAllPatientProfilesQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetClinicalHistoryIdByPatientIdQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetPatientProfileByIdQuery;

import java.util.List;
import java.util.Optional;

public interface PatientProfileQueryService {
    Optional<PatientProfile> handle(GetPatientProfileByIdQuery query);

    List<PatientProfile> handle(GetAllPatientProfilesQuery query);

    Long handle(GetClinicalHistoryIdByPatientIdQuery query);
}
