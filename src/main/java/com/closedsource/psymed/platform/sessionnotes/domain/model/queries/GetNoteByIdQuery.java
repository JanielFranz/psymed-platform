package com.closedsource.psymed.platform.sessionnotes.domain.model.queries;

public record GetNoteByIdQuery(Long id) {

    public GetNoteByIdQuery {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Note ID must be greater than 0");
        }
    }
}
