package com.closedsource.psymed.platform.sessionnotes.interfaces.rest;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllNotesQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetNoteByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.NoteCommandService;
import com.closedsource.psymed.platform.sessionnotes.domain.service.NoteQueryService;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.CreateNoteResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.resources.NoteResource;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.CreateNoteCommandFromResourceAssembler;
import com.closedsource.psymed.platform.sessionnotes.interfaces.rest.transform.NoteFromEntityAssembler;
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
 * REST controller responsible for handling note-related operations.
 */
@RestController
@RequestMapping(value = "/api/v1/notes", produces = APPLICATION_JSON_VALUE)
@Tag(name = "Notes", description = "Operations related to notes explaining the description and symptoms")
public class NoteController {

    private final NoteCommandService noteCommandService;
    private final NoteQueryService noteQueryService;

    /**
     * Constructor to inject services required for note operations.
     *
     * @param noteCommandService The service responsible for handling note commands.
     * @param noteQueryService   The service responsible for handling note queries.
     */
    public NoteController(NoteCommandService noteCommandService, NoteQueryService noteQueryService) {
        this.noteCommandService = noteCommandService;
        this.noteQueryService = noteQueryService;
    }

    /**
     * Retrieves all notes.
     *
     * @return A ResponseEntity containing a list of NoteResources.
     */
    @Operation(summary = "Get all notes", description = "Retrieve all notes")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Notes found")
    })
    @GetMapping
    public ResponseEntity<List<NoteResource>> getAllNotes() {
        List<Note> notes = noteQueryService.handle(new GetAllNotesQuery());
        List<NoteResource> noteResources = notes.stream()
                .map(NoteFromEntityAssembler::toResourceFromEntity)
                .toList();
        return ResponseEntity.ok(noteResources);
    }

    /**
     * Retrieves a note by its ID.
     *
     * @param id The ID of the note.
     * @return A ResponseEntity containing the NoteResource or a not found status.
     */
    @Operation(summary = "Get note by ID", description = "Retrieve a note using its ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Note found"),
            @ApiResponse(responseCode = "404", description = "Note not found")
    })
    @GetMapping("/{id}")
    public ResponseEntity<NoteResource> getNoteById(@PathVariable Long id) {
        Optional<Note> note = noteQueryService.handle(new GetNoteByIdQuery(id));
        return note
                .map(n -> ResponseEntity.ok(NoteFromEntityAssembler.toResourceFromEntity(n)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Creates a note with details about description and symptoms.
     *
     * @param resource The resource containing note creation details.
     * @return A ResponseEntity containing the created NoteResource or a bad request status.
     */
    @Operation(summary = "Create a note", description = "Create a note with a description and symptoms")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Note created"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PostMapping
    public ResponseEntity<NoteResource> createNote(@RequestBody CreateNoteResource resource) {
        Optional<Note> note = noteCommandService.handle(
                CreateNoteCommandFromResourceAssembler.toCommandFromResource(resource));
        return note
                .map(n -> new ResponseEntity<>(NoteFromEntityAssembler.toResourceFromEntity(n), CREATED))
                .orElseGet(() -> ResponseEntity.badRequest().build());
    }
}
