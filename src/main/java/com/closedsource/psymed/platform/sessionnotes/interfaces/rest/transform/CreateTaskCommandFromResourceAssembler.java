package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateTaskResource;

/**
 * A utility class that converts a {@link CreateTaskResource} object into a {@link CreateTaskCommand} object.
 */
public class CreateTaskCommandFromResourceAssembler {

    /**
     * Converts the {@link CreateTaskResource} to a {@link CreateTaskCommand}.
     *
     * @param resource The {@link CreateTaskResource} containing the task details.
     * @return A {@link CreateTaskCommand} object populated with data from the resource.
     */
    public static CreateTaskCommand toCommandFromResource(CreateTaskResource resource) {
        return new CreateTaskCommand(
                resource.title(),
                resource.description(),
                resource.completionStatus());
    }
}
