package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTreatmentTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateTreatmentTaskResource;

/**
 * A utility class that converts a {@link CreateTreatmentTaskResource} object into a {@link CreateTreatmentTaskCommand} object.
 */
public class CreateTreatmentTaskFromResourceAssembler {

    /**
     * Converts the {@link CreateTreatmentTaskResource} to a {@link CreateTreatmentTaskCommand}.
     *
     * @param resource The {@link CreateTreatmentTaskResource} containing the treatment task details.
     * @return A {@link CreateTreatmentTaskCommand} object populated with data from the resource.
     */
    public static CreateTreatmentTaskCommand toCommandFromResource(CreateTreatmentTaskResource resource) {
        return new CreateTreatmentTaskCommand(
                resource.title(),
                resource.date(),
                resource.tasks());
    }
}
