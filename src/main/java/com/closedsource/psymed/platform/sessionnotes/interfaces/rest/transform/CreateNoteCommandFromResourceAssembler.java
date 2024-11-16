package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateNoteCommand;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateNoteResource;

/**
 * A utility class that converts a {@link CreateNoteResource} object into a {@link CreateNoteCommand} object.
 */
public class CreateNoteCommandFromResourceAssembler {

    /**
     * Converts the {@link CreateNoteResource} to a {@link CreateNoteCommand}.
     *
     * @param resource The {@link CreateNoteResource} containing the note details.
     * @return A {@link CreateNoteCommand} object populated with the data from the resource.
     */
    public static CreateNoteCommand toCommandFromResource(CreateNoteResource resource) {
        return new CreateNoteCommand(
                resource.description(),
                resource.symptom());
    }
}
