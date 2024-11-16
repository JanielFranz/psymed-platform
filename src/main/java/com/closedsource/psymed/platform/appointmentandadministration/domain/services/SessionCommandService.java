package com.closedsource.psymed.platform.appointmentandadministration.domain.services;

import com.closedsource.psymed.platform.appointmentandadministration.domain.model.aggregates.Session;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.commands.CreateSessionCommand;
import com.closedsource.psymed.platform.appointmentandadministration.domain.model.commands.UpdateSessionNoteCommand;

import java.util.Optional;

/**
 * Service to handle commands related to appointments.
 * @summary
 * This service is responsible for handling commands related to creating, updating, and deleting appointments.
 */
public interface SessionCommandService {

    /**
     * Handle the command to create an appointment.
     *
     * @param command the command to create an appointment
     * @return the created appointment
     * @throws IllegalArgumentException if the command is invalid
     * @see CreateSessionCommand
     */
    Optional<Session> handle(CreateSessionCommand command);

    /**
     * Handle the command to create an appointment.
     *
     * @param command the command to create an appointment
     * @return the created appointment
     * @throws IllegalArgumentException if the command is invalid
     * @see UpdateSessionNoteCommand
     */
    Optional<Session> handle(UpdateSessionNoteCommand command);
}
