package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.ProfessionalTreatmentTaskResource;

/**
 * A utility class for converting a {@link ProfessionalTreatmentTask} entity into a {@link ProfessionalTreatmentTaskResource}.
 */
public class ProfessionalTreatmentTaskEntityAssembler {

    /**
     * Converts a {@link ProfessionalTreatmentTask} entity to a {@link ProfessionalTreatmentTaskResource}.
     *
     * @param entity The {@link ProfessionalTreatmentTask} entity containing the professional treatment task details.
     * @return A {@link ProfessionalTreatmentTaskResource} representing the professional treatment task in a format suitable for REST responses.
     */
    public static ProfessionalTreatmentTaskResource toResourceFromEntity(ProfessionalTreatmentTask entity) {
        return new ProfessionalTreatmentTaskResource(
                entity.getId(),
                entity.getTreatmentTasks());
    }
}
