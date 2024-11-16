// Código 1: Interfaz para el servicio de comandos de notas en la plataforma Psymed.

package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateNoteCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;

import java.util.Optional;

/**
 * Service interface to handle commands related to notes in the Psymed platform.
 *
 * @summary
 * This interface defines the contract for handling commands that create notes.
 */
public interface NoteCommandService {

    /**
     * Processes the command to create a new note.
     *
     * @param command the command containing details to create the note
     * @return an Optional containing the created Note, or empty if the creation fails
     * @see CreateNoteCommand
     */
    Optional<Note> handle(CreateNoteCommand command);
}
