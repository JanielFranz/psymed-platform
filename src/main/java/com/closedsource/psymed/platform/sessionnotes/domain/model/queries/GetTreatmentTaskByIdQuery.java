package com.closedsource.psymed.platform.sessionnotes.domain.model.queries;

public record GetTreatmentTaskByIdQuery(Long id){

    public GetTreatmentTaskByIdQuery {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("TreatmentTask ID must be greater than 0");
        }
    }
}
