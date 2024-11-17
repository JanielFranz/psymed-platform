package com.closedsource.psymed.platform.profiles.domain.services;

import com.closedsource.psymed.platform.profiles.domain.model.aggregates.PatientProfile;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetAllPatientProfilesQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetPatientProfileByAccountIdQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetPatientProfileByIdQuery;
import com.closedsource.psymed.platform.profiles.domain.model.queries.GetProfessionalProfileByAccountIdQuery;

import java.util.List;
import java.util.Optional;

public interface PatientProfileQueryService {
    Optional<PatientProfile> handle(GetPatientProfileByIdQuery query);
    List<PatientProfile> handle(GetAllPatientProfilesQuery query);
    Optional<PatientProfile> handle(GetPatientProfileByAccountIdQuery query);
}
