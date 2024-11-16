package com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories;


import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {
}
