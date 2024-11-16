package com.closedsource.psymed.platform.sessionnotes.application.commandservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateTaskCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TaskCommandService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.TaskRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TaskCommandServiceImpl implements TaskCommandService {

    private final TaskRepository taskRepository;

    public TaskCommandServiceImpl(TaskRepository taskRepository) {
        this.taskRepository = taskRepository;
    }

    @Override
    public Optional<Task> handle(CreateTaskCommand command) {

        var task = new Task(command);
        var taskResult = taskRepository.save(task);

        return Optional.of(taskResult);
    }
}
