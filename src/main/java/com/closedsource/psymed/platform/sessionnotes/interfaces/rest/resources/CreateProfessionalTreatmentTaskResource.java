package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;

import java.util.List;

/**
 * A resource class representing the details needed to create a list of professional treatment tasks in the Psymed platform.
 *
 * @param treatmentTasks The list of treatment tasks for the professional. Cannot be null or empty.
 */
public record CreateProfessionalTreatmentTaskResource(
        List<TreatmentTask> treatmentTasks) {

    /**
     * Constructor for CreateProfessionalTreatmentTaskResource.
     * Validates that 'treatmentTasks' is not null or empty.
     *
     * @throws IllegalArgumentException if 'treatmentTasks' is null or empty.
     */
    public CreateProfessionalTreatmentTaskResource {

        if (treatmentTasks == null || treatmentTasks.isEmpty()) {
            throw new IllegalArgumentException("treatmentTasks cannot be null or empty");
        }
    }
}
