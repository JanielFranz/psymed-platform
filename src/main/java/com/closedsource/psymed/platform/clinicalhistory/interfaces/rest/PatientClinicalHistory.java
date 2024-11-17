package com.closedsource.psymed.platform.clinicalhistory.interfaces.rest;

import com.closedsource.psymed.platform.clinicalhistory.domain.model.aggregates.ClinicalHistory;
import com.closedsource.psymed.platform.clinicalhistory.domain.model.queries.GetClinicalHistoryByPatientIdQuery;
import com.closedsource.psymed.platform.clinicalhistory.domain.service.ClinicalHistoryQueryService;
import com.closedsource.psymed.platform.clinicalhistory.interfaces.rest.resources.ClinicalHistoryResource;
import com.closedsource.psymed.platform.clinicalhistory.interfaces.rest.transform.ClinicalHistoryResourceFromEntityAssembler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(value = "api/v1/patients/{id}/clinical-histories", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name="Patients Clinical History", description = "The Patient Clinical History Controller")
public class PatientClinicalHistory {
    private final ClinicalHistoryQueryService clinicalHistoryQueryService;

    public PatientClinicalHistory(ClinicalHistoryQueryService clinicalHistoryQueryService) {
        this.clinicalHistoryQueryService = clinicalHistoryQueryService;
    }

    @Operation(summary = "Get all clinical histories by patient id", description = "Get all clinical histories by patient id")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "The clinical histories were retrieved successfully"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "The request was not successful"),
    })
    @GetMapping
    public ResponseEntity<List<ClinicalHistoryResource>> getClinicalHistoriesByPatientEmail(@PathVariable Long id) {
        var query = new GetClinicalHistoryByPatientIdQuery(id);
        Optional<ClinicalHistory> clinicalHistories = this.clinicalHistoryQueryService.handle(query);

        if (clinicalHistories.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        List<ClinicalHistoryResource> resources = clinicalHistories.stream().map(ClinicalHistoryResourceFromEntityAssembler::toResourceFromEntity).toList();
        return ResponseEntity.ok(resources);
    }
}
