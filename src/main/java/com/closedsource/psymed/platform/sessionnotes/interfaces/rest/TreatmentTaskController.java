package com.closedsource.psymed.platform.sessionnotes.interfaces.rest;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.TreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllTreatmentTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetTreatmentTaskByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TreatmentTaskCommandService;
import com.closedsource.psymed.platform.sessionnotes.domain.service.TreatmentTaskQueryService;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateTreatmentTaskResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.TreatmentTaskResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.CreateTreatmentTaskFromResourceAssembler;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.TreatmentTaskFromEntityAssembler;
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
 * REST controller responsible for handling treatment task-related operations.
 */
@RestController
@RequestMapping(value = "/api/v1/treatment_tasks", produces = APPLICATION_JSON_VALUE)
@Tag(name = "Treatment Tasks", description = "Operations related to treatment tasks")
public class TreatmentTaskController {

    private final TreatmentTaskCommandService treatmentTaskCommandService;
    private final TreatmentTaskQueryService treatmentTaskQueryService;

    /**
     * Constructor to inject services required for treatment task operations.
     *
     * @param treatmentTaskCommandService The service responsible for handling treatment task commands.
     * @param treatmentTaskQueryService   The service responsible for handling treatment task queries.
     */
    public TreatmentTaskController(TreatmentTaskCommandService treatmentTaskCommandService,
                                   TreatmentTaskQueryService treatmentTaskQueryService) {
        this.treatmentTaskCommandService = treatmentTaskCommandService;
        this.treatmentTaskQueryService = treatmentTaskQueryService;
    }

    /**
     * Retrieves all treatment tasks.
     *
     * @return A ResponseEntity containing a list of TreatmentTaskResources.
     */
    @Operation(summary = "Get all treatment tasks", description = "Retrieve all treatment tasks")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Treatment tasks found")
    })
    @GetMapping
    public ResponseEntity<List<TreatmentTaskResource>> getAllTreatmentTasks() {

        List<TreatmentTask> treatmentTasks = treatmentTaskQueryService.handle(new GetAllTreatmentTaskQuery());
        List<TreatmentTaskResource> treatmentTaskResources = treatmentTasks.stream()
                .map(TreatmentTaskFromEntityAssembler::toResourceFromEntity)
                .toList();
        return ResponseEntity.ok(treatmentTaskResources);
    }

    /**
     * Retrieves a treatment task by its ID.
     *
     * @param id The ID of the treatment task.
     * @return A ResponseEntity containing the TreatmentTaskResource or a not found status.
     */
    @Operation(summary = "Get treatment task by ID", description = "Retrieve a treatment task using its ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Treatment task found"),
            @ApiResponse(responseCode = "404", description = "Treatment task not found")
    })
    @GetMapping("/{id}")
    public ResponseEntity<TreatmentTaskResource> getTreatmentTaskById(@PathVariable Long id) {

        Optional<TreatmentTask> treatmentTask = treatmentTaskQueryService.handle(new GetTreatmentTaskByIdQuery(id));

        return treatmentTask
                .map(t -> ResponseEntity.ok(TreatmentTaskFromEntityAssembler.toResourceFromEntity(t)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Creates a new treatment task.
     *
     * @param resource The resource containing treatment task creation details.
     * @return A ResponseEntity containing the created TreatmentTaskResource or a bad request status.
     */
    @Operation(summary = "Create a treatment task", description = "Create a new treatment task")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Treatment task created"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PostMapping
    public ResponseEntity<TreatmentTaskResource> createTreatmentTask(@RequestBody CreateTreatmentTaskResource resource) {

        Optional<TreatmentTask> treatmentTask = treatmentTaskCommandService.handle(
                CreateTreatmentTaskFromResourceAssembler.toCommandFromResource(resource));

        return treatmentTask
                .map(t -> new ResponseEntity<>(TreatmentTaskFromEntityAssembler.toResourceFromEntity(t), CREATED))
                .orElseGet(() -> ResponseEntity.badRequest().build());
    }
}
