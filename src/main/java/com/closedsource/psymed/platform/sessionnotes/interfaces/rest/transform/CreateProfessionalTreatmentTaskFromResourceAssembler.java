package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateProfessionalTreatmentTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateProfessionalTreatmentTaskResource;

/**
 * A utility class that converts a {@link CreateProfessionalTreatmentTaskResource} object into a
 * {@link CreateProfessionalTreatmentTaskCommand} object.
 */
public class CreateProfessionalTreatmentTaskFromResourceAssembler {

    /**
     * Converts the {@link CreateProfessionalTreatmentTaskResource} to a {@link CreateProfessionalTreatmentTaskCommand}.
     *
     * @param resource The {@link CreateProfessionalTreatmentTaskResource} containing the professional treatment task details.
     * @return A {@link CreateProfessionalTreatmentTaskCommand} populated with data from the resource.
     */
    public static CreateProfessionalTreatmentTaskCommand toCommandFromResource(
            CreateProfessionalTreatmentTaskResource resource) {
        return new CreateProfessionalTreatmentTaskCommand(
                resource.treatmentTasks());
    }
}
