package com.closedsource.psymed.platform.sessionnotes.domain.model.commands;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;

import java.util.List;

public record CreateProfessionalTreatmentTaskCommand(List<TreatmentTask> treatmentTasks) {
}
