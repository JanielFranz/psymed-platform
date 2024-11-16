package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

/**
 * A resource class representing the details needed to create a task in the Psymed platform.
 *
 * @param title            The title of the task. Cannot be null or empty.
 * @param description      The description of the task. Cannot be null.
 * @param completionStatus The completion status of the task (true if completed).
 */
public record CreateTaskResource(
        String title,
        String description,
        boolean completionStatus) {

    /**
     * Constructor for CreateTaskResource.
     * Validates that 'title' is not null or empty, and 'description' is not null.
     *
     * @throws IllegalArgumentException if 'title' is null or empty, or if 'description' is null.
     */
    public CreateTaskResource {

        if (title == null || title.isBlank()) {
            throw new IllegalArgumentException("Title cannot be null or empty");
        }

        if (description == null) {
            throw new IllegalArgumentException("Description cannot be null or empty");
        }
    }
}
