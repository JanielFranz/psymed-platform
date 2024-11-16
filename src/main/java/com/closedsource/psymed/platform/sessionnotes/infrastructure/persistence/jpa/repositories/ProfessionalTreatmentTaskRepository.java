package com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProfessionalTreatmentTaskRepository extends JpaRepository<ProfessionalTreatmentTask, Long> {
}
