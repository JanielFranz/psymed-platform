package com.closedsource.psymed.platform.sessionnotes.application.queryservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetAllNotesQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.model.queries.GetNoteByIdQuery;
import com.closedsource.psymed.platform.sessionnotes.domain.service.NoteQueryService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.NoteRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class NoteQueryServiceImpl implements NoteQueryService {

    private final NoteRepository noteRepository;

    public NoteQueryServiceImpl(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    @Override
    public Optional<Note> handle(GetNoteByIdQuery query) {
        return noteRepository.findById(query.id());
    }

    @Override
    public List<Note> handle(GetAllNotesQuery query) {
        return noteRepository.findAll();
    }

}
