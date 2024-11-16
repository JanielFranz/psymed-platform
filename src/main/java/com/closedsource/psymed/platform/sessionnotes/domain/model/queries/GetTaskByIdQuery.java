package com.closedsource.psymed.platform.sessionnotes.domain.model.queries;

public record GetTaskByIdQuery(Long id) {

    public GetTaskByIdQuery {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("TreatmentTask ID must be greater than 0");
        }
    }
}
