package com.closedsource.psymed.platform.sessionnotes.domain.model.commands;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;

import java.util.Date;
import java.util.List;

public record CreateTreatmentTaskCommand(String title, Date date, List<Task> tasks) {
}
