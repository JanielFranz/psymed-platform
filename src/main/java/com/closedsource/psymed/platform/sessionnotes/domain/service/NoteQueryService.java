package com.closedsource.psymed.platform.sessionnotes.domain.service;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllNotesQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetNoteByIdQuery;

import java.util.List;
import java.util.Optional;

/**
 * Service to handle queries related to notes.
 * This service fetches note data based on various criteria.
 */
public interface NoteQueryService {

    /**
     * Handle the query to get a note by its ID.
     *
     * @param query the query object containing the note ID
     * @return an optional containing the note if found
     */
    Optional<Note> handle(GetNoteByIdQuery query);

    /**
     * Handle the query to get all notes.
     *
     * @param query the query object to fetch all notes
     * @return a list of all notes
     */
    List<Note> handle(GetAllNotesQuery query);
}
