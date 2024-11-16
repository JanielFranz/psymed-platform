package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;

import java.util.List;

public record ProfessionalTreatmentTaskResource (
        Long id,
        List<TreatmentTask> treatmentTasks
){
}
