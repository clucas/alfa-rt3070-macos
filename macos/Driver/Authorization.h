#ifndef ALFA_AUTHORIZATION_H
#define ALFA_AUTHORIZATION_H

#include <string.h>

inline bool AlfaAuthorizedIdentity(const char *application, size_t applicationLength,
    const char *team, size_t teamLength,
    const char *expectedApplication, const char *expectedTeam) {
    return application && team && expectedApplication && expectedTeam &&
        expectedApplication[0] && expectedTeam[0] &&
        applicationLength == strlen(expectedApplication) && teamLength == strlen(expectedTeam) &&
        memcmp(application, expectedApplication, applicationLength) == 0 &&
        memcmp(team, expectedTeam, teamLength) == 0;
}

#endif
