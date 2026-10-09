package authengine

func ValidateImportedCredential(credential *Credential) error {
	if err := validateCredential(credential); err != nil {
		return err
	}
	if !safeOpaque(credential.Sauth.SDKUID, 512) || !safeOpaque(credential.Sauth.DeviceID, 512) {
		return ErrInvalidCredential
	}
	if credential.Sauth.Platform == "pc" {
		if credential.Sauth.UDID != "" && !safeOpaque(credential.Sauth.UDID, 512) {
			return ErrInvalidCredential
		}
	} else if !validAndroidUDID(credential.Sauth.UDID) {
		return ErrInvalidCredential
	}
	return nil
}
