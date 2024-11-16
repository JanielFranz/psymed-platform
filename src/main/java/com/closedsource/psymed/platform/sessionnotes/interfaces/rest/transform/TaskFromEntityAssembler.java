package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.TaskResource;

/**
 * A utility class for converting a {@link Task} entity into a {@link TaskResource}.
 */
public class TaskFromEntityAssembler {

    /**
     * Converts a {@link Task} entity to a {@link TaskResource}.
     *
     * @param entity The {@link Task} entity containing the task details.
     * @return A {@link TaskResource} representing the task in a format suitable for REST responses.
     */
    public static TaskResource toResourceFromEntity(Task entity) {
        return new TaskResource(
                entity.getId(),
                entity.getTitle(),
                entity.getDescription(),
                entity.isCompletionStatus());
    }
}
