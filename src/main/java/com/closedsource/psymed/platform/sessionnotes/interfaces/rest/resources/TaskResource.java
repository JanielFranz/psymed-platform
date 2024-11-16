package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

public record TaskResource(
        Long id,
        String title,
        String description,
        boolean completionStatus
) {
}
