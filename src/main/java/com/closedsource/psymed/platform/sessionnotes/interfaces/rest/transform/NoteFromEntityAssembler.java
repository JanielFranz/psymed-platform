package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.NoteResource;

/**
 * A utility class for converting a {@link Note} entity into a {@link NoteResource}.
 */
public class NoteFromEntityAssembler {

    /**
     * Converts a {@link Note} entity to a {@link NoteResource}.
     *
     * @param entity The {@link Note} entity containing the note details.
     * @return A {@link NoteResource} representing the note in a format suitable for REST responses.
     */
    public static NoteResource toResourceFromEntity(Note entity) {
        return new NoteResource(
                entity.getId(),
                entity.getDescription(),
                entity.getSymptoms());
    }
}
