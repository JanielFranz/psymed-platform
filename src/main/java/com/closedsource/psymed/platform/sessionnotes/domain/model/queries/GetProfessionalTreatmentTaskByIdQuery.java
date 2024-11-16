package com.closedsource.psymed.platform.sessionnotes.domain.model.queries;

public record GetProfessionalTreatmentTaskByIdQuery (Long id){

    public GetProfessionalTreatmentTaskByIdQuery {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("ProfessionalTreatmentTask ID must be greater than 0");
        }
    }
}
