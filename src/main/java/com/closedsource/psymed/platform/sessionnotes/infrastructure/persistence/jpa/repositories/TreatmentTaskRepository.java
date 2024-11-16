package com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TreatmentTaskRepository extends JpaRepository<TreatmentTask, Long> {
}
