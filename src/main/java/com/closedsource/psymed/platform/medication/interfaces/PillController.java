package com.closedsource.psymed.platform.medication.interfaces;

import com.closedsource.psymed.platform.medication.domain.model.commands.DeletePillsCommand;
import com.closedsource.psymed.platform.medication.domain.model.queries.GetAllPillsQuery;
import com.closedsource.psymed.platform.medication.domain.model.queries.GetPillsByIdQuery;
import com.closedsource.psymed.platform.medication.domain.services.PillCommandService;
import com.closedsource.psymed.platform.medication.domain.services.PillQueryService;
import com.closedsource.psymed.platform.medication.interfaces.rest.resources.CreatePillResource;
import com.closedsource.psymed.platform.medication.interfaces.rest.resources.PillResource;
import com.closedsource.psymed.platform.medication.interfaces.rest.transform.CreatePillCommandFromResourceAssembler;
import com.closedsource.psymed.platform.medication.interfaces.rest.transform.PillResourceFromEntityAssembler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping(value = "/api/v1/pills", produces = APPLICATION_JSON_VALUE)
@Tag(name = "Pill", description = "All medication related endpoints")
public class PillController {

    private final PillCommandService pillCommandService;
    private final PillQueryService pillQueryService;


    public PillController(PillCommandService pillCommandService, PillQueryService pillQueryService) {
        this.pillCommandService = pillCommandService;
        this.pillQueryService = pillQueryService;
    }


    @Operation(summary = "Create a new Pill")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Course created"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "404", description = "Course not found")
    })
    @PostMapping
    public ResponseEntity<PillResource> createMedication(@RequestBody CreatePillResource createPillResource){
        var createMedicationCommand = CreatePillCommandFromResourceAssembler.toCommandFromResource(createPillResource);
        var medicationId = pillCommandService.handle(createMedicationCommand);
        if (medicationId == null || medicationId == 0L) return ResponseEntity.badRequest().build();
        var getMedicationByIdQuery = new GetPillsByIdQuery(medicationId);
        var medication = pillQueryService.handle(getMedicationByIdQuery);

        if(medication.isEmpty()) return ResponseEntity.notFound().build();
        var medicationEntity = medication.get();
        var medicationSource = PillResourceFromEntityAssembler.toResourceFromEntity(medicationEntity);
        return new ResponseEntity<>(medicationSource, HttpStatus.CREATED);
    }

    @Operation(summary = "Get all Pills")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Courses found"),
            @ApiResponse(responseCode = "404", description = "Courses not found")
    })
    @GetMapping
    public ResponseEntity<List<PillResource>> getAllMedications(){
        var getAllMedicationsQuery = new GetAllPillsQuery();
        var medications = pillQueryService.handle(getAllMedicationsQuery);
        var medicationResources = medications.stream()
                .map(PillResourceFromEntityAssembler::toResourceFromEntity)
                .toList();
        return ResponseEntity.ok(medicationResources);
    }

    @Operation(summary = "Delete a Pill")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Course deleted"),
            @ApiResponse(responseCode = "404", description = "Course not found")
    })
    @DeleteMapping("/{pillId}")
    public ResponseEntity<?> deleteMedication(@PathVariable Long pillId){
        var deleteMedicationCommand = new DeletePillsCommand(pillId);
        pillCommandService.handle(deleteMedicationCommand);
        return ResponseEntity.ok("Medication with given id successfully deleted");
    }









}
