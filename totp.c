#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <linux/limits.h>
#include <liboath/oath.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define SAFE_FREE(ptr) safe_free((void**)&ptr)

#define SECRETS_DIRECTORY "/etc/totp_secrets/"
#define OTP_WINDOW 1

#define PAM_PROMPT "TOTP Token:"
#define PATH_TRAVERSAL_MESSAGE "Path traversal attempt detected:"
#define INVALID_OTP_MESSAGE "Invalid TOTP for user"

int check_totp_for_user(pam_handle_t *pamh, const char *const user, const char *const otp_code);

void safe_free(void **buffer);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;

    int verification_status = PAM_AUTH_ERR;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user)
        return verification_status;


    char *otp_token = NULL;
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp_token, PAM_PROMPT) != PAM_SUCCESS || !otp_token) {
        if(otp_token) memset(otp_token, 0, strlen(otp_token));
        SAFE_FREE(otp_token);
    
        return verification_status;
    }

    verification_status = check_totp_for_user(pamh, user, otp_token);

    if(otp_token) memset(otp_token, 0, strlen(otp_token));
    SAFE_FREE(otp_token);
    
    return verification_status;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

int check_totp_for_user(pam_handle_t *pamh, const char *const user, const char *const otp_code) {

    if (oath_init() != OATH_OK)
        return PAM_AUTH_ERR;
        

    char secret_b32[UINT8_MAX];
    char path[PATH_MAX];
    
    char *secret_decoded = NULL;
    size_t secret_decoded_length;

    int status = PAM_AUTH_ERR;
    
    do {

        snprintf(path, sizeof(path), SECRETS_DIRECTORY "%s", user);
        
        char resolved_path[PATH_MAX];
        if (realpath(path, resolved_path) == NULL) 
            break;
        
        if (strncmp(resolved_path, SECRETS_DIRECTORY, strlen(SECRETS_DIRECTORY)) != 0) {
            pam_syslog(pamh, LOG_ALERT, PATH_TRAVERSAL_MESSAGE " %s", resolved_path);
            
            break;
        }
        
        FILE *file = fopen(resolved_path, "r");
        if (!file)
            break;
        
        if (!fgets(secret_b32, sizeof(secret_b32), file)) {
            fclose(file);

            break;
        }
        
        fclose(file);
        
        secret_b32[strcspn(secret_b32, "\r\n")] = 0; // Clean newline
        
        const size_t secret_length = strlen(secret_b32);
        
        int decode_result = oath_base32_decode(secret_b32, secret_length, &secret_decoded, &secret_decoded_length);
        if(decode_result != OATH_OK)
            break;
        
        int validation_result = oath_totp_validate(secret_decoded, secret_decoded_length, time(NULL), OATH_TOTP_DEFAULT_TIME_STEP_SIZE, OATH_TOTP_DEFAULT_START_TIME, OTP_WINDOW, otp_code);
        
        if(oath_done() != OATH_OK)
            break;
        
        if (validation_result >= 0) {
            status = PAM_SUCCESS;
            
            break;
        }

        pam_syslog(pamh, LOG_WARNING, INVALID_OTP_MESSAGE " %s", user);

    } while(0);

    memset(secret_b32, 0, sizeof(secret_b32));
    if (secret_decoded) memset(secret_decoded, 0, secret_decoded_length);
    
    SAFE_FREE(secret_decoded);

    return status;
}

void safe_free(void **buffer) {
    free(*buffer); 
    *buffer = NULL;
}