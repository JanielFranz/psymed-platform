package com.closedsource.psymed.platform.medication.infrastructure.persistence.jpa.repositories;

import com.closedsource.psymed.platform.medication.domain.model.aggregates.Pills;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PillRepository extends JpaRepository<Pills, Long> {
    Optional<Pills> findByName(String name);
    boolean existsByName(String name);


    //boolean existsById(Long id);
}
