package com.closedsource.psymed.platform.medication.domain.model.commands;

public record CreateMedicationCommand(String name, String description) {

    public CreateMedicationCommand{
        if(name == null || name.isBlank())
            throw new IllegalArgumentException("Medication name cannot be null or empty");
        if(description == null || description.isBlank())
            throw new IllegalArgumentException("Medication description cannot be null or empty");
    }
}
