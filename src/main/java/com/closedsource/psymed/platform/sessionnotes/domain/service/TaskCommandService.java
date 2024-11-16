// Código 3: Interfaz para el servicio de comandos de tareas en la plataforma Psymed.

package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;

import java.util.Optional;

/**
 * Service interface to handle commands related to tasks in the Psymed platform.
 *
 * @summary
 * This interface defines the contract for handling commands that create tasks.
 */
public interface TaskCommandService {

    /**
     * Processes the command to create a new task.
     *
     * @param command the command containing details to create the task
     * @return an Optional containing the created Task, or empty if the creation fails
     * @see CreateTaskCommand
     */
    Optional<Task> handle(CreateTaskCommand command);
}
