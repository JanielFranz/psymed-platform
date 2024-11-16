// Código 4: Interfaz para el servicio de comandos de tareas de tratamiento en la plataforma Psymed.

package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTreatmentTaskCommand;

import java.util.Optional;

/**
 * Service interface to handle commands related to treatment tasks in the Psymed platform.
 *
 * @summary
 * This interface defines the contract for handling commands that create treatment tasks.
 */
public interface TreatmentTaskCommandService {

    /**
     * Processes the command to create a new treatment task.
     *
     * @param command the command containing details to create the treatment task
     * @return an Optional containing the created TreatmentTask, or empty if creation fails
     * @see CreateTreatmentTaskCommand
     */
    Optional<TreatmentTask> handle(CreateTreatmentTaskCommand command);
}
