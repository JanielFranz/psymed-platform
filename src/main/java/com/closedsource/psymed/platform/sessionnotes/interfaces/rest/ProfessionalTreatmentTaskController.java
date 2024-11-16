package com.closedsource.psymed.platform.sessionnotes.interfaces.rest;

import com.closedsource.psymed.platform.sessionnotes.domain.model.aggregate.ProfessionalTreatmentTask;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllProfessionalTreatmentTaskQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetProfessionalTreatmentTaskByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.ProfessionalTreatmentTaskCommandService;
import com.closedsource.psymed.platform.sessionnotes.domain.service.ProfessionalTreatmentTaskQueryService;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateProfessionalTreatmentTaskResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.ProfessionalTreatmentTaskResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.CreateProfessionalTreatmentTaskFromResourceAssembler;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.ProfessionalTreatmentTaskEntityAssembler;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/api/v1/professional_treatment_tasks", produces = APPLICATION_JSON_VALUE)
@Tag(name = "Professional treatment task", description = "Professional treatment tasks")
public class ProfessionalTreatmentTaskController {

    private final ProfessionalTreatmentTaskCommandService professionalTreatmentTaskCommandService;
    private final ProfessionalTreatmentTaskQueryService professionalTreatmentTaskQueryService;

    public ProfessionalTreatmentTaskController(ProfessionalTreatmentTaskCommandService professionalTreatmentTaskCommandService, ProfessionalTreatmentTaskQueryService professionalTreatmentTaskQueryService) {
        this.professionalTreatmentTaskCommandService = professionalTreatmentTaskCommandService;
        this.professionalTreatmentTaskQueryService = professionalTreatmentTaskQueryService;
    }

    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Professional treatment tasks found"),})
    @GetMapping
    public ResponseEntity<List<ProfessionalTreatmentTask>> getAllProfessionalTreatmentTasks(){

        List<ProfessionalTreatmentTask> professionalTreatmentTasks = professionalTreatmentTaskQueryService.handle(new GetAllProfessionalTreatmentTaskQuery());

        if (professionalTreatmentTasks.isEmpty()) return ResponseEntity.notFound().build();

        return ResponseEntity.ok(professionalTreatmentTasks);
    }


    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Treatment task found"),
            @ApiResponse(responseCode = "404", description = "Treatment task not found")
    })
    @GetMapping("/{id}")
    public ResponseEntity<ProfessionalTreatmentTaskResource> getTaskById(@PathVariable Long id){

        Optional<ProfessionalTreatmentTask> professionalTreatmentTask = professionalTreatmentTaskQueryService.handle(new GetProfessionalTreatmentTaskByIdQuery(id));

        return professionalTreatmentTask
                .map(t -> ResponseEntity.ok(ProfessionalTreatmentTaskEntityAssembler.toResourceFromEntity(t)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Treatment task created"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PostMapping
    public ResponseEntity<ProfessionalTreatmentTaskResource> createTask(CreateProfessionalTreatmentTaskResource resource) {

        Optional<ProfessionalTreatmentTask> professionalTreatmentTask = professionalTreatmentTaskCommandService.handle(
                CreateProfessionalTreatmentTaskFromResourceAssembler.toCommandFromResource(resource));

        return professionalTreatmentTask
                .map(t -> ResponseEntity.ok(ProfessionalTreatmentTaskEntityAssembler.toResourceFromEntity(t)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
