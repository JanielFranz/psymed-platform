//package com.closedsource.psymed.platform.appointmentandadministration.interfaces.rest;
//
//import com.closedsource.psymed.platform.appointmentandadministration.domain.model.aggregates.Session;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.model.commands.UpdateSessionNoteCommand;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetAllSessionsByPatientIdQuery;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetAllSessionsByProfessionalIdQuery;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetSessionByIdQuery;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.model.queries.GetSessionByPatientIdAndSessionIdQuery;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.services.SessionCommandService;
//import com.closedsource.psymed.platform.appointmentandadministration.domain.services.SessionQueryService;
//import com.closedsource.psymed.platform.appointmentandadministration.interfaces.rest.resources.CreateSessionResource;
//import com.closedsource.psymed.platform.appointmentandadministration.interfaces.rest.resources.SessionResource;
//import com.closedsource.psymed.platform.appointmentandadministration.interfaces.rest.transform.CreateSessionCommandFromResourceAssembler;
//import com.closedsource.psymed.platform.appointmentandadministration.interfaces.rest.transform.SessionResourceFromEntityAssembler;
//import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
//import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetNoteByIdQuery;
//import com.closedsource.psymed.platform.sessionnotes.domain.service.NoteQueryService;
//import io.swagger.v3.oas.annotations.Operation;
//import io.swagger.v3.oas.annotations.responses.ApiResponse;
//import io.swagger.v3.oas.annotations.responses.ApiResponses;
//import io.swagger.v3.oas.annotations.tags.Tag;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.List;
//import java.util.Optional;
//
//import static org.springframework.http.HttpStatus.CREATED;
//import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
//
///**
// * REST controller responsible for handling session-related operations between patients and professionals.
// */
//@RestController
//@RequestMapping(value = "/api/v1/sessions", produces = APPLICATION_JSON_VALUE)
//@Tag(name = "Sessions", description = "Operations related to sessions between patients and professionals")
//public class SessionController {
//
//    private final SessionCommandService sessionCommandService;
//    private final SessionQueryService sessionQueryService;
//
//    private final NoteQueryService noteQueryService;
//
//
//    public SessionController(SessionCommandService sessionCommandService,
//                             SessionQueryService sessionQueryService, NoteQueryService noteQueryService) {
//        this.sessionCommandService = sessionCommandService;
//        this.sessionQueryService = sessionQueryService;
//        this.noteQueryService = noteQueryService;
//    }
//
//    /**
//     * Retrieves all sessions.
//     *
//     * @return A ResponseEntity containing a list of sessions or a not found status.
//     */
//    @Operation(summary = "Get all sessions",
//            description = "Retrieve all sessions")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "Sessions found"),
//            @ApiResponse(responseCode = "404", description = "No sessions found")
//    })
//    @GetMapping
//    public ResponseEntity<List<SessionResource>> getAllSessions() {
//        var sessions = sessionQueryService.handle(); // Fixed method call
//        if (sessions.isEmpty()) return ResponseEntity.notFound().build();
//        var sessionResources = sessions.stream()
//                .map(SessionResourceFromEntityAssembler::toResourceFromEntity)
//                .toList();
//        return ResponseEntity.ok(sessionResources);
//    }
//
//    /**
//     * Retrieves a session by its ID.
//     *
//     * @param id The ID of the session.
//     * @return A ResponseEntity containing the session or a not found status.
//     */
//    @Operation(summary = "Get session by ID",
//            description = "Retrieve a session using its ID")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "Session found"),
//            @ApiResponse(responseCode = "404", description = "Session not found")
//    })
//    @GetMapping("/{id}")
//    public ResponseEntity<SessionResource> getSessionById(@PathVariable Long id) {
//        Optional<Session> session = sessionQueryService.handle(new GetSessionByIdQuery(id));
//        return session
//                .map(s -> ResponseEntity.ok(SessionResourceFromEntityAssembler.toResourceFromEntity(s)))
//                .orElseGet(() -> ResponseEntity.notFound().build());
//    }
//
//
//
//    /**
//     * Retrieves a specific session for a patient using the session ID.
//     *
//     * @param patientId The ID of the patient.
//     * @param id        The ID of the session.
//     * @return A ResponseEntity containing the session or a not found status.
//     */
//    @Operation(summary = "Get session by patient ID and session ID",
//            description = "Retrieve a specific session for a patient using the session ID")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "Session found"),
//            @ApiResponse(responseCode = "404", description = "Session not found")
//    })
//    @GetMapping("/patient/{patientId}/session/{id}")
//    public ResponseEntity<SessionResource> getSessionByPatientIdAndId(
//            @PathVariable String patientId, @PathVariable Long id) {
//
//        var query = new GetSessionByPatientIdAndSessionIdQuery(patientId, id);
//        Optional<Session> session = sessionQueryService.handle(query);
//        return session
//                .map(s -> ResponseEntity.ok(SessionResourceFromEntityAssembler.toResourceFromEntity(s)))
//                .orElseGet(() -> ResponseEntity.notFound().build());
//    }
//}
