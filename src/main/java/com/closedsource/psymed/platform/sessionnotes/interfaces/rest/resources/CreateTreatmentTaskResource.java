package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;

import java.util.Date;
import java.util.List;

/**
 * A record representing the resource for creating a Treatment Task.
 */
public record CreateTreatmentTaskResource(
        String title,
        Date date,
        List<Task> tasks
) {

    /**
     * Compact constructor that validates the input parameters.
     *
     * @throws IllegalArgumentException if any required field is null or invalid.
     */
    public CreateTreatmentTaskResource {
        if (title == null || title.isBlank()) {
            throw new IllegalArgumentException("Title cannot be null or empty");
        }

        if (date == null) {
            throw new IllegalArgumentException("Date cannot be null");
        }

        if (tasks == null || tasks.isEmpty()) {
            throw new IllegalArgumentException("Tasks cannot be null or empty");
        }
    }
}
