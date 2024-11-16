package com.closedsource.psymed.platform.profiles.interfaces.acl.service;

import com.closedsource.psymed.platform.profiles.domain.model.commands.CheckPatientProfileByIdCommand;
import com.closedsource.psymed.platform.profiles.domain.model.commands.CheckProfessionalProfileByIdCommand;
import com.closedsource.psymed.platform.profiles.domain.services.PatientProfileCommandService;
import com.closedsource.psymed.platform.profiles.domain.services.ProfessionalProfileCommandService;
import com.closedsource.psymed.platform.profiles.interfaces.acl.ProfilesContextFacade;
import org.springframework.stereotype.Service;

@Service
public class ProfilesContextFacadeImpl implements ProfilesContextFacade {
    //#region DI
    private final PatientProfileCommandService patientProfileCommandService;
    private final ProfessionalProfileCommandService professionalProfileCommandService;

    public ProfilesContextFacadeImpl(PatientProfileCommandService patientProfileCommandService,
                                     ProfessionalProfileCommandService professionalProfileCommandService) {
        this.patientProfileCommandService = patientProfileCommandService;
        this.professionalProfileCommandService = professionalProfileCommandService;
    }

    //#endregion

    public boolean verifyPatientProfile(Long patientId) {
        var verifyPatientCommand = new CheckPatientProfileByIdCommand(patientId);
        var exists = patientProfileCommandService.handle(verifyPatientCommand);
        //To improve
        if(!exists) {
            throw new RuntimeException("Patient profile does not exist");
        }
        return exists;
    }

    public boolean verifyProfessionalProfile(Long professionalId) {
        var verifyProfessionalCommand = new CheckProfessionalProfileByIdCommand(professionalId);
        var exists = professionalProfileCommandService.handle(verifyProfessionalCommand);
        //To improve
        if(!exists) {
            throw new RuntimeException("Professional profile does not exist");
        }
        return exists;
    }


}
