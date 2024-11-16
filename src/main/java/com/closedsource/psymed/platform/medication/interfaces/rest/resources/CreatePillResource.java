package com.closedsource.psymed.platform.medication.interfaces.rest.resources;

public record CreatePillResource(String name, String description) {

    public CreatePillResource {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Name cannot be null or blank");
        if (description == null || description.isBlank()) throw new IllegalArgumentException("Description cannot be null or blank");
    }
}
