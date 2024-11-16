package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

/**
 * A resource class representing the details needed to create a note in the Psymed platform.
 *
 * @param description The description of the note. Cannot be null or empty.
 * @param symptom     The symptom associated with the note. Cannot be null or empty.
 */
public record CreateNoteResource(
        String description,
        String symptom) {

    /**
     * Constructor for CreateNoteResource.
     * Validates that both 'description' and 'symptom' are not null or empty.
     *
     * @throws IllegalArgumentException if 'description' or 'symptom' are null or empty.
     */
    public CreateNoteResource {

        if (description == null || description.isBlank()) {
            throw new IllegalArgumentException("description cannot be null or empty");
        }

        if (symptom == null || symptom.isBlank()) {
            throw new IllegalArgumentException("symptom cannot be null or empty");
        }
    }
}
