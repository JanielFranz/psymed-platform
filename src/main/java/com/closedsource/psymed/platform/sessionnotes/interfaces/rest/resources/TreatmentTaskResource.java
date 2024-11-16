package com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;

import java.util.Date;
import java.util.List;

public record TreatmentTaskResource(
        Long id,
        String title,
        Date date,
        List<Task> tasks
){
}
