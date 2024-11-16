package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.TreatmentTaskResource;

/**
 * A utility class for converting a {@link TreatmentTask} entity into a {@link TreatmentTaskResource}.
 */
public class TreatmentTaskFromEntityAssembler {

    /**
     * Converts a {@link TreatmentTask} entity to a {@link TreatmentTaskResource}.
     *
     * @param entity The {@link TreatmentTask} entity containing the treatment task details.
     * @return A {@link TreatmentTaskResource} representing the treatment task in a format suitable for REST responses.
     */
    public static TreatmentTaskResource toResourceFromEntity(TreatmentTask entity) {
        return new TreatmentTaskResource(
                entity.getId(),
                entity.getTitle(),
                entity.getDate(),
                entity.getTasks());
    }
}
