package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

public record NoteResource(
        Long id,
        String description,
        String symptom) {
}
