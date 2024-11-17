package com.closedsource.psymed.platform.clinicalhistory.interfaces.rest;

import com.closedsource.psymed.platform.clinicalhistory.domain.model.aggregates.ClinicalHistory;
import com.closedsource.psymed.platform.clinicalhistory.domain.model.queries.GetClinicalHistoryByIdQuery;
import com.closedsource.psymed.platform.clinicalhistory.domain.model.queries.GetClinicalHistoryByPatientIdQuery;
import com.closedsource.psymed.platform.clinicalhistory.domain.service.ClinicalHistoryCommandService;
import com.closedsource.psymed.platform.clinicalhistory.domain.service.ClinicalHistoryQueryService;
import com.closedsource.psymed.platform.clinicalhistory.interfaces.rest.resources.ClinicalHistoryResource;
import com.closedsource.psymed.platform.clinicalhistory.interfaces.rest.resources.CreateClinicalHistoryResource;
import com.closedsource.psymed.platform.clinicalhistory.interfaces.rest.transform.ClinicalHistoryResourceFromEntityAssembler;
import com.closedsource.psymed.platform.clinicalhistory.interfaces.rest.transform.CreateClinicalHistoryCommandFromResourceAssembler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

@ApiResponses(value = {
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "The request was not successful"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "An unexpected error occurred on the server side"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "The request was not authorized"),
        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "The request was forbidden"),
})
@RestController
@RequestMapping(value ="/api/v1/clinical-histories", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Clinical History", description = "The Clinical History Controller")
public class ClinicalHistoryController {
    private final ClinicalHistoryCommandService clinicalHistoryCommandService;
    private final ClinicalHistoryQueryService clinicalHistoryQueryService;

    public ClinicalHistoryController(ClinicalHistoryCommandService clinicalHistoryCommandService, ClinicalHistoryQueryService clinicalHistoryQueryService) {
        this.clinicalHistoryCommandService = clinicalHistoryCommandService;
        this.clinicalHistoryQueryService = clinicalHistoryQueryService;
    }
    @Operation(summary = "Create a new clinical history", description = "Create a new clinical history with the given data")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "The clinical history was created successfully"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "The request was not successful"),
    })
    @PostMapping
    public ResponseEntity<ClinicalHistoryResource> createClinicalHistory(@RequestBody CreateClinicalHistoryResource clinicalHistoryResource) {
        Optional<ClinicalHistory> clinicalHistory = this.clinicalHistoryCommandService.handle(CreateClinicalHistoryCommandFromResourceAssembler.toCommandFromResource(clinicalHistoryResource));
        return clinicalHistory.map(ClinicalHistoryResourceFromEntityAssembler::toResourceFromEntity)
                .map(resource -> ResponseEntity.status(CREATED).body(resource))
                .orElseGet(() -> ResponseEntity.badRequest().build());
    }

    @Operation(summary = "Get a clinical history by id", description = "Get a clinical history by id")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "The clinical history was retrieved successfully"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "The request was not successful"),
    })
    @GetMapping("/{id}")
    public ResponseEntity<ClinicalHistoryResource> getClinicalHistoryById(@PathVariable Long id) {
        var query = new GetClinicalHistoryByIdQuery(id);
        Optional<ClinicalHistory> clinicalHistory = this.clinicalHistoryQueryService.handle(query);

        return clinicalHistory.map(p -> new ResponseEntity<>(ClinicalHistoryResourceFromEntityAssembler.toResourceFromEntity(p), OK))
                .orElseGet(() -> ResponseEntity.badRequest().build());
    }




}
