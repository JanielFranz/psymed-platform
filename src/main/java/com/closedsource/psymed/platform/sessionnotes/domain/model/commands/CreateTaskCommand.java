package com.closedsource.psymed.platform.sessionnotes.domain.model.commands;

public record CreateTaskCommand(String title, String description, boolean completionStatus) {
}
