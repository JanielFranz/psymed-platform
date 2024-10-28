package com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries;

public record GetNoteByIdQuery(Long id) {

    public GetNoteByIdQuery {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Session ID must be greater than 0");
        }
    }
}
