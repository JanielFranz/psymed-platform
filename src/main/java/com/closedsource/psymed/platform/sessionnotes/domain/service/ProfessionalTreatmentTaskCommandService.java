// Código 2: Interfaz para el servicio de comandos de tareas de tratamiento profesional en la plataforma Psymed.

package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateProfessionalTreatmentTaskCommand;

import java.util.Optional;

/**
 * Service interface to handle commands related to professional treatment tasks in the Psymed platform.
 *
 * @summary
 * This interface defines the contract for handling commands that create professional treatment tasks.
 */
public interface ProfessionalTreatmentTaskCommandService {

    /**
     * Processes the command to create a new professional treatment task.
     *
     * @param command the command containing details to create the professional treatment task
     * @return an Optional containing the created ProfessionalTreatmentTask, or empty if creation fails
     * @see CreateProfessionalTreatmentTaskCommand
     */
    Optional<ProfessionalTreatmentTask> handle(CreateProfessionalTreatmentTaskCommand command);
}
