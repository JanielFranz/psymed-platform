package com.closedsource.psymed.platform.profiles.infrastructure.persistence.jpa.repositories;

import com.closedsource.psymed.platform.profiles.domain.model.aggregates.PatientProfile;
import com.closedsource.psymed.platform.profiles.domain.model.valueobjects.Email;
import org.springframework.data.jpa.repository.JpaRepository;
import com.closedsource.psymed.platform.profiles.domain.model.valueobjects.AccountId;

import java.util.Optional;

public interface PatientProfileRepository extends JpaRepository<PatientProfile, Long> {
    boolean existsByEmail(Email emailAddress);
    Optional<PatientProfile> findByAccountId(AccountId accountId);
    Long findClinicalHistoryIdById(Long patientId);
    Optional<PatientProfile> findByProfessionalId(Long accountId);
}
