package com.closedsource.psymed.platform.sessionnotes.application.commandservices;

import com.closedsource.psymed.platform.sessionnotes.domain.model.commands.CreateNoteCommand;
import com.closedsource.psymed.platform.sessionnotes.domain.model.entities.Note;
import com.closedsource.psymed.platform.sessionnotes.domain.service.NoteCommandService;
import com.closedsource.psymed.platform.sessionnotes.infrastructure.persistence.jpa.repositories.NoteRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class NoteCommandServiceImpl implements NoteCommandService {

    private final NoteRepository noteRepository;

    public NoteCommandServiceImpl(NoteRepository noteRepository){
        this.noteRepository = noteRepository;
    }

    @Override
    public Optional<Note> handle(CreateNoteCommand command) {
        var note = new Note(command);
        var createNotes = noteRepository.save(note);

        return Optional.of(createNotes);
    }
}
