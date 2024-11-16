package com.closedsource.psymed.platform.sessionnotes.interfaces.rest;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Task;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetTaskByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TaskCommandService;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TaskQueryService;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateTaskResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.TaskResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.CreateTaskCommandFromResourceAssembler;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.TaskFromEntityAssembler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * REST controller responsible for handling task-related operations.
 */
@RestController
@RequestMapping(value = "/api/v1/tasks", produces = APPLICATION_JSON_VALUE)
@Tag(name = "Tasks", description = "Tasks related to medical details")
public class TaskController {

    private final TaskCommandService taskCommandService;
    private final TaskQueryService taskQueryService;

    /**
     * Constructor to inject services required for task operations.
     *
     * @param taskCommandService The service responsible for handling task commands.
     * @param taskQueryService   The service responsible for handling task queries.
     */
    public TaskController(TaskCommandService taskCommandService, TaskQueryService taskQueryService) {
        this.taskCommandService = taskCommandService;
        this.taskQueryService = taskQueryService;
    }

    /**
     * Retrieves all tasks.
     *
     * @return A ResponseEntity containing a list of TaskResources.
     */
    @Operation(summary = "Get all tasks", description = "Retrieve all tasks")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Tasks found")
    })
    @GetMapping
    public ResponseEntity<List<TaskResource>> getAllTasks() {
        List<Task> tasks = taskQueryService.handle(new GetAllTaskQuery());
        List<TaskResource> taskResources = tasks.stream()
                .map(TaskFromEntityAssembler::toResourceFromEntity)
                .toList();
        return ResponseEntity.ok(taskResources);
    }

    /**
     * Retrieves a task by its ID.
     *
     * @param id The ID of the task.
     * @return A ResponseEntity containing the TaskResource or a not found status.
     */
    @Operation(summary = "Get task by ID", description = "Retrieve a task using its ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Task found"),
            @ApiResponse(responseCode = "404", description = "Task not found")
    })
    @GetMapping("/{id}")
    public ResponseEntity<TaskResource> getTaskById(@PathVariable Long id) {
        Optional<Task> task = taskQueryService.handle(new GetTaskByIdQuery(id));
        return task
                .map(t -> ResponseEntity.ok(TaskFromEntityAssembler.toResourceFromEntity(t)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Creates a new task.
     *
     * @param resource The resource containing task creation details.
     * @return A ResponseEntity containing the created TaskResource or a bad request status.
     */
    @Operation(summary = "Create a task", description = "Create a new task with medical details")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Task created"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PostMapping
    public ResponseEntity<TaskResource> createTask(@RequestBody CreateTaskResource resource) {
        Optional<Task> task = taskCommandService.handle(
                CreateTaskCommandFromResourceAssembler.toCommandFromResource(resource));
        return task
                .map(t -> new ResponseEntity<>(TaskFromEntityAssembler.toResourceFromEntity(t), CREATED))
                .orElseGet(() -> ResponseEntity.badRequest().build());
    }
}
